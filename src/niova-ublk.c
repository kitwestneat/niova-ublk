// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <pthread.h>
#include <liburing.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include <sys/types.h>
#include <ublk_cmd.h>
#include <unistd.h>

#include "ublksrv.h"
#include "ublksrv_utils.h"

#define UBLKSRV_TGT_TYPE_DEMO  0

#include <niova/log.h>
#include <uuid/uuid.h>
#include <niova/nclient.h>
#include <niova/nclient_private.h>

#define NIOVA_QD 32
#define NIOVA_MAX_IO 128*1024

// defined by linux
#define SECTOR_SHIFT 9

int niovaSectorBits = 12; // XXX should there be a nclient fn?
bool diskStarted = false;

struct niova_tgt_opts
{
	uint64_t nto_size;
	const char *nto_vdev_uuid;
	const char *nto_tgt_uuid;
};

static struct ublksrv_ctrl_dev *this_dev;

/*
 * XXX this causes the program to hang forever
static void sig_handler(int sig)
{
	fprintf(stderr, "got signal %d\n", sig);
	ublksrv_ctrl_stop_dev(this_dev);
}
*/

/*
 */
static int q_id = 0;
static void *niova_queue_runner(void *arg)
{
	const struct ublksrv_dev *dev = arg;
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	unsigned dev_id = dinfo->dev_id;
	const struct ublksrv_queue *q;

	q = ublksrv_queue_init(dev, q_id, dev->tgt.tgt_data);
	if (!q) {
		fprintf(stderr, "ublk dev %d queue %d init queue failed\n",
				dinfo->dev_id, q_id);
		return NULL;
	}

	fprintf(stdout, "tid %d: ublk dev %d queue %d started\n",
			ublksrv_gettid(),
			dev_id, q->q_id);

	while (ublksrv_process_io(q) >= 0);

	fprintf(stdout, "ublk dev %d queue %d exited\n", dev_id, q->q_id);
	ublksrv_queue_deinit(q);
	return NULL;
}

static void niova_set_ublk_parameters(struct ublksrv_ctrl_dev *cdev,
									  const struct ublksrv_dev *dev,
									  int block_size_bits)
 {
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(cdev);
	struct ublk_params p = {
		.types = UBLK_PARAM_TYPE_BASIC,
		.basic = {
			.logical_bs_shift	= block_size_bits,
			.physical_bs_shift	= block_size_bits,
			.io_opt_shift		= block_size_bits,
			.io_min_shift		= block_size_bits,
			.max_sectors		= info->max_io_buf_bytes >> block_size_bits,
			.dev_sectors		= dev->tgt.dev_size >> block_size_bits,
		},
	};
	struct ublksrv_tgt_base_json tgt_json = {
		.type = UBLKSRV_TGT_TYPE_DEMO,
		.dev_size = dev->tgt.dev_size,
	};
	strcpy(tgt_json.name, "niova");

	int rc = ublksrv_ctrl_set_params(cdev, &p);
	if (rc)
		fprintf(stderr, "dev %d set basic parameter failed %d\n",
				info->dev_id, rc);
}

static int niova_opt_parse(int argc, char **argv, struct niova_tgt_opts *tgt_opts)
{
	static const struct option longopts[] = {
		{ "size",		1,	NULL, 's' },
		{ "vdev",		1,	NULL, 'v' },
		{ "tgt",		1,	NULL, 't' },
		{ NULL }
	};
	int opt;
	int found = 0;

	while ((opt = getopt_long(argc, argv, "s:v:t:",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 's':
			tgt_opts->nto_size = atoll(optarg);
			found |= 1;
			break;
		case 'v':
			tgt_opts->nto_vdev_uuid = optarg;
			found |= 2;
			break;
		case 't':
			tgt_opts->nto_tgt_uuid = optarg;
			found |= 4;
			break;
		}
	}

	return found == 7 ? 0 : -EINVAL;
}

static int niova_open(struct ublksrv_dev *dev, struct niova_tgt_opts *opts)
{
	SIMPLE_LOG_MSG(LL_TRACE, "enter niova_open");

	niova_block_client_t *client = NULL;
	struct niova_block_client_xopts xopts = {0};
	struct vdev_info vdi;
	char *config;
	int rc;

	NIOVA_ASSERT(dev && opts->nto_tgt_uuid && opts->nto_vdev_uuid);

	uuid_parse(opts->nto_vdev_uuid, xopts.npcx_opts.vdev_uuid);
	uuid_parse(opts->nto_tgt_uuid, xopts.npcx_opts.target_uuid);

	size_t nvblks = dev->tgt.dev_size >> niovaSectorBits;
	vdi.vdi_mode = VDEV_MODE_CLIENT_TEST;
	vdi.vdi_num_vblks = nvblks;

	rc = niova_block_client_set_private_opts(&xopts, &vdi, NULL, NULL);
	if (rc) {
		error(0, rc, "niova_block_client_set_private_opts()");
		goto err;
	}

	rc = NiovaBlockClientNew(&client, &xopts.npcx_opts);
	if (rc) {
		error(0, rc, "error creating niova client");
		goto err;
	}
	SIMPLE_LOG_MSG(LL_TRACE, "created client@%p", client);

	dev->tgt.tgt_data = client;

	return 0;
err:
	return -EINVAL;
}

static int niova_ublk_start(struct ublksrv_ctrl_dev *ctrl_dev)
{
	int ret, i;
	const struct ublksrv_dev *dev;
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ctrl_dev);

	dev = ublksrv_dev_init(ctrl_dev);
	if (!dev) {
		return -ENOMEM;
	}

	niova_set_ublk_parameters(ctrl_dev, dev, niovaSectorBits);

	// queue runner must be running when start_dev is called
	// -- linux add_disk looks for a partition table, so IO thread must be active
	pthread_t io_thread;
	pthread_create(&io_thread, NULL, niova_queue_runner, (void *)dev);

	ret = ublksrv_ctrl_start_dev(ctrl_dev, getpid());
	if (ret < 0)
		goto fail;

	diskStarted = true;

	pthread_join(io_thread, NULL);

 fail:
	 ublksrv_dev_deinit(dev);

	 return ret;
}

static int niova_init_tgt(struct ublksrv_dev *dev, int type, int argc,
		char *argv[])
{
	SIMPLE_LOG_MSG(LL_TRACE, "enter niova_init_tgt");

	struct niova_tgt_opts tgt_opts;
	const struct ublksrv_ctrl_dev_info *info =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	struct ublksrv_tgt_info *tgt = &dev->tgt;

	if (type != UBLKSRV_TGT_TYPE_DEMO)
		return -1;

	int rc = niova_opt_parse(argc, argv, &tgt_opts);
	FATAL_IF(rc, "niova_opt_parse: rc=%d", rc);

	tgt->dev_size = tgt_opts.nto_size;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

	if (tgt->dev_size == 0)
		return -EINVAL;

	rc = niova_open(dev, &tgt_opts);
	FATAL_IF(rc, "niova_open(), rc=%d", rc);

	return 0;
}

struct niova_cb_data {
	int 						  ncd_tag;
	ssize_t 					  ncd_rc;
	const struct ublksrv_queue   *ncd_q;
	bool						  ncd_completed;
	const struct ublksrv_io_desc *ncd_iod;
	struct iovec				  ncd_iov;
	SLIST_ENTRY(niova_cb_data)	  ncd_entry;
};
SLIST_HEAD(niova_cb_data_slist, niova_cb_data) niovaCompletedOps =
	SLIST_HEAD_INITIALIZER(niova_cb_data_slist);

pthread_mutex_t cb_mutex = PTHREAD_MUTEX_INITIALIZER;

// run in niova context
static void niova_rw_cb(void *arg, ssize_t rc)
{
	struct niova_cb_data *ncd = arg;
	const struct ublksrv_io_desc *iod = ncd->ncd_iod;

	SIMPLE_LOG_MSG(LL_TRACE, "niova_rw_cb: rc=%zd start=%llu base=%llu nr=%d",
			rc, iod->start_sector, iod->addr, iod->nr_sectors);
	SIMPLE_LOG_MSG(LL_TRACE, "LCK locking mutex");
	niova_mutex_lock(&cb_mutex);
	ncd->ncd_rc = rc;
	SLIST_INSERT_HEAD(&niovaCompletedOps, ncd, ncd_entry);
	SIMPLE_LOG_MSG(LL_TRACE, "LCK unlocking mutex");
	niova_mutex_unlock(&cb_mutex);

	// ublksrv_complete_io must be run in io thread, so send an event
	SIMPLE_LOG_MSG(LL_TRACE, "sending event q@%p", ncd->ncd_q);
	ublksrv_queue_send_event(ncd->ncd_q);

}

int niovaWatchdogTimeSec = 5;

/* XXX the kernel worker will hang if we there is an error during startup and we don't respond */
static void *niova_rw_watchdog(void *arg) {
	struct niova_cb_data *ncd = arg;
	sleep(niovaWatchdogTimeSec);

	SIMPLE_LOG_MSG(LL_TRACE, "LCK locking mutex");
	niova_mutex_lock(&cb_mutex);
	if (ncd->ncd_completed)
		free(ncd);
	else {
		SIMPLE_LOG_MSG(LL_TRACE, "niova_rw_watchdog: timed out, completing");
		ublksrv_complete_io(ncd->ncd_q, ncd->ncd_tag, -EIO);
	}
	SIMPLE_LOG_MSG(LL_TRACE, "LCK unlocking mutex");
	niova_mutex_unlock(&cb_mutex);

	return NULL;
}

static int niova_rw(bool is_read, const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	SIMPLE_FUNC_ENTRY(LL_TRACE);

	niova_block_client_t *client = q->private_data;
	const struct ublksrv_io_desc *iod = data->iod;

	struct niova_cb_data *ncd = calloc(1, sizeof(struct niova_cb_data));
	ncd->ncd_tag = data->tag;
	ncd->ncd_q = q;
	ncd->ncd_completed = false;
	ncd->ncd_iod = iod;

	// ublk uses 512 sectors
	unsigned long long start_vblk = iod->start_sector >> (niovaSectorBits - SECTOR_SHIFT);

	ncd->ncd_iov.iov_base = (void *)iod->addr;
	ncd->ncd_iov.iov_len = iod->nr_sectors << SECTOR_SHIFT;
	int iov_cnt = 1;

	SIMPLE_LOG_MSG(LL_TRACE, "niova_rw: cli@%p op=%s start=%llu base=%llu len=%zu",
			client, is_read ? "read" : "write", start_vblk, iod->addr, ncd->ncd_iov.iov_len);

	int rc = is_read ?
		NiovaBlockClientReadv(client, start_vblk, &ncd->ncd_iov, iov_cnt,
					  niova_rw_cb, ncd):
		NiovaBlockClientWritev(client, start_vblk, &ncd->ncd_iov, iov_cnt,
					   niova_rw_cb, ncd);

	/*
	pthread_t watchdog;
	pthread_create(&watchdog, NULL, niova_rw_watchdog, ncd);
	pthread_detach(watchdog);
	*/

	SIMPLE_FUNC_EXIT(LL_TRACE);

	return rc < 0 ? -EIO : 0;
}

static int niova_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	const struct ublksrv_io_desc *iod = data->iod;

	SIMPLE_LOG_MSG(LL_TRACE, "enter niova_handle_io_async, started=%d", diskStarted);

	if (false && !diskStarted) { // XXX
		ublksrv_complete_io(q, data->tag, iod->nr_sectors << SECTOR_SHIFT);
		return 0;
	}

	unsigned ublk_op = ublksrv_get_op(iod);
	switch (ublk_op) {
		case UBLK_IO_OP_FLUSH:
		case UBLK_IO_OP_WRITE_ZEROES:
		case UBLK_IO_OP_DISCARD:
			// XXX to implement
			ublksrv_complete_io(q, data->tag, iod->nr_sectors << SECTOR_SHIFT);
			break;
		case UBLK_IO_OP_READ:
			niova_rw(true, q, data);
			break;
		case UBLK_IO_OP_WRITE:
			niova_rw(false, q, data);
			break;
		default:
			return -EINVAL;
	}

	return 0;
}

static void niova_handle_event(const struct ublksrv_queue *q)
{
	struct niova_cb_data *ncd;

	SIMPLE_LOG_MSG(LL_TRACE, "LCK locking mutex");
	niova_mutex_lock(&cb_mutex);
	SIMPLE_LOG_MSG(LL_TRACE, "list is_empty=%d", SLIST_EMPTY(&niovaCompletedOps));

	while (!SLIST_EMPTY(&niovaCompletedOps)) {
		ncd = SLIST_FIRST(&niovaCompletedOps);
		SLIST_REMOVE_HEAD(&niovaCompletedOps, ncd_entry);

		const struct ublksrv_io_desc *iod = ncd->ncd_iod;

		SIMPLE_LOG_MSG(LL_TRACE, "completing io: rc=%zd start=%llu base=%llu nr=%d",
			ncd->ncd_rc, iod->start_sector, iod->addr, iod->nr_sectors);
		ublksrv_complete_io(ncd->ncd_q, ncd->ncd_tag, ncd->ncd_rc);
		free(ncd);
	}
	SIMPLE_LOG_MSG(LL_TRACE, "LCK unlocking mutex");
	niova_mutex_unlock(&cb_mutex);

	// requeue event handler
	ublksrv_queue_handled_event(q);
	SIMPLE_FUNC_EXIT(LL_TRACE);
}

static struct ublksrv_tgt_type niova_tgt_type = {
	.type	= UBLKSRV_TGT_TYPE_DEMO,
	.name	=  "niova",
	.init_tgt = niova_init_tgt,
	.handle_io_async = niova_handle_io_async,
	.handle_event = niova_handle_event,
};

int main(int argc, char *argv[])
{
	struct ublksrv_dev_data data = {
		.dev_id = -1,
		.max_io_buf_bytes = NIOVA_MAX_IO,
		.nr_hw_queues = 1,
		.queue_depth = NIOVA_QD,
		.tgt_type = "niova",
		.tgt_ops = &niova_tgt_type,
		.flags = 0,
		.tgt_argc = argc,
		.tgt_argv = argv,
		.ublksrv_flags = UBLKSRV_F_NEED_EVENTFD,
	};
	struct ublksrv_ctrl_dev *dev;
	int ret;

	/*
	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		error(EXIT_FAILURE, errno, "signal");
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		error(EXIT_FAILURE, errno, "signal");
		*/

	log_level_set(5);
	ublk_set_debug_mask(-1);

	SIMPLE_LOG_MSG(LL_DEBUG, "calling ublksrv_ctrl_init");

	dev = ublksrv_ctrl_init(&data);
	if (!dev)
		error(EXIT_FAILURE, ENODEV, "ublksrv_ctrl_init");

	/* ugly, but signal handler needs this_dev */
	this_dev = dev;

	SIMPLE_LOG_MSG(LL_DEBUG, "calling ublksrv_ctrl_add_dev(%p)", dev);
	ret = ublksrv_ctrl_add_dev(dev);
	if (ret < 0) {
		error(0, -ret, "can't add dev %d", data.dev_id);
		goto fail;
	}

	ublksrv_ctrl_dump(dev, NULL);

	SIMPLE_LOG_MSG(LL_DEBUG, "calling niova_ublk_start(%p)", dev);
	ret = niova_ublk_start(dev);
	if (ret < 0 && ret != -EINTR) {
		error(0, -ret, "can't start daemon");
		goto fail_del_dev;
	}

	ublksrv_ctrl_del_dev(dev);
	ublksrv_ctrl_deinit(dev);
	exit(EXIT_SUCCESS);

 fail_del_dev:
	ublksrv_ctrl_del_dev(dev);
 fail:
	ublksrv_ctrl_deinit(dev);

	exit(EXIT_FAILURE);
}
