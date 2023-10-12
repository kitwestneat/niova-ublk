cmake_minimum_required(VERSION 3.5)

set(CMAKE_INSTALL_RPATH "/usr/local/lib")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

project(niova-ublk)

add_executable(niova-ublk src/niova-ublk.c)

link_directories(niova-ublk PUBLIC /usr/local/lib)
find_library(NIOVA_BLOCK_CLIENT_LIB niova_block_client)
find_library(NIOVA_LIB niova)
find_library(UUID_LIB uuid)
find_library(URING_LIB uring)
find_library(PTHREAD_LIB pthread)
target_link_libraries(niova-ublk ublksrv ${UUID_LIB} ${NIOVA_LIB} ${NIOVA_BLOCK_CLIENT_LIB} ${URING_LIB} ${PTHREAD_LIB} )

