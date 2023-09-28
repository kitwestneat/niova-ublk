// SPDX-License-Identifier: MIT or GPL-2.0-only

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <pthread.h>
#include <getopt.h>
#include <stdarg.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "ublksrv.h"
#include "ublksrv_utils.h"

#define UBLKSRV_TGT_TYPE_DEMO  0

#include <niova/log.h>
#include <uuid/uuid.h>
#include <niova/nclient.h>
#include <niova/nclient_private.h>

#define NBUFFER_MAX 8192
#define UT2_DEFAULT_FILE_SIZE ((size_t)1 << 31)
#define REQUEST_SIZE_IN_BLKS 1
#define REQUEST_SIZE_IN_BLKS_MAX BUFFER_SIZE_MAX_NBLKS
#define REQUEST_SIZE_MAX_RANDOM_IN_BLKS BUFFER_SIZE_MAX_NBLKS
#define NIOVA_QD 32
#define NIOVA_MAX_IO 128*1024

#define NUM_TASKS 128

#define CONN_HANDLE_DEF_CREDITS 16
#define URING_ENTRIES_DEF 32

int niovaSectorBits = 12; // XXX should there be a nclient fn?

struct niova_tgt_opts
{
	uint64_t nto_size;
	const char *nto_vdev_uuid;
	const char *nto_tgt_uuid;
};

static struct ublksrv_ctrl_dev *this_dev;

static void sig_handler(int sig)
{
	fprintf(stderr, "got signal %d\n", sig);
	ublksrv_ctrl_stop_dev(this_dev);
}

/*
 */
static void *niova_queue_runner(unsigned short q_id, const struct ublksrv_dev *dev)
{
	const struct ublksrv_ctrl_dev_info *dinfo =
		ublksrv_ctrl_get_dev_info(ublksrv_get_ctrl_dev(dev));
	unsigned dev_id = dinfo->dev_id;
	const struct ublksrv_queue *q;

	q = ublksrv_queue_init(dev, q_id, NULL);
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

	while ((opt = getopt_long(argc, argv, "s:",
				  longopts, NULL)) != -1) {
		switch (opt) {
		case 's':
			tgt_opts->nto_size = atoll(optarg);
			break;
		case 'v':
			tgt_opts->nto_vdev_uuid = optarg;
			break;
		case 't':
			tgt_opts->nto_tgt_uuid = optarg;
			break;
		}
	}

	return -EINVAL;
}

static int niova_open(struct ublksrv_dev *dev, unsigned long long size,
					  const char *tgt_uuid, const char *vdev_uuid)
{
    SIMPLE_LOG_MSG(LL_TRACE, "enter niova_open");

	niova_block_client_t *client = NULL;
    struct niova_block_client_opts opts;
	char *config;
	int rc;

	NIOVA_ASSERT(dev && tgt_uuid && vdev_uuid);

	uuid_parse(vdev_uuid, opts.vdev_uuid);
	uuid_parse(tgt_uuid, opts.target_uuid);

	rc = NiovaBlockClientNew(&client, &opts);
	if (rc) {
		error(0, rc, "error creating niova client");
		goto err;
	}

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

    SIMPLE_LOG_MSG(LL_DEBUG, "calling ublksrv_dev_init(%p)", ctrl_dev);
	dev = ublksrv_dev_init(ctrl_dev);
	if (!dev) {
		return -ENOMEM;
	}

	niova_set_ublk_parameters(ctrl_dev, dev, niovaSectorBits);

	/* everything is fine now, start us */
    SIMPLE_LOG_MSG(LL_DEBUG, "calling ublksrv_ctrl_start_dev(%p)", ctrl_dev);
	ret = ublksrv_ctrl_start_dev(ctrl_dev, getpid());
	if (ret < 0)
		goto fail;

	ublksrv_ctrl_get_info(ctrl_dev);

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

	tgt->dev_size = tgt_opts.nto_size;
	tgt->tgt_ring_depth = info->queue_depth;
	tgt->nr_fds = 0;

    // niova queue runner?

	return 0;
}

static int niova_handle_io_async(const struct ublksrv_queue *q,
		const struct ublk_io_data *data)
{
	const struct ublksrv_io_desc *iod = data->iod;

    SIMPLE_LOG_MSG(LL_TRACE, "enter niova_handle_io_async");

	return 0;
}

static struct ublksrv_tgt_type niova_tgt_type = {
	.type	= UBLKSRV_TGT_TYPE_DEMO,
	.name	=  "niova",
	.init_tgt = niova_init_tgt,
	.handle_io_async = niova_handle_io_async,
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
	};
	struct ublksrv_ctrl_dev *dev;
	int ret;

	if (signal(SIGTERM, sig_handler) == SIG_ERR)
		error(EXIT_FAILURE, errno, "signal");
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		error(EXIT_FAILURE, errno, "signal");

    log_level_set(5);
    ublk_set_debug_mask(255);

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

    SIMPLE_LOG_MSG(LL_DEBUG, "calling niova_ublk_start(%p)", dev);
	ret = niova_ublk_start(dev);
	if (ret < 0) {
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
