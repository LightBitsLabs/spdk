#!/usr/bin/env bash

testdir=$(readlink -f $(dirname $0))
rootdir=$(readlink -f $testdir/../../..)
source $rootdir/scripts/autotest_common.sh
source $rootdir/test/nvmf/common.sh

MALLOC_BDEV_SIZE=64
MALLOC_BLOCK_SIZE=512

rpc_py="python $rootdir/scripts/rpc.py"

set -e

if ! rdma_nic_available; then
        echo "no NIC for nvmf test"
        exit 0
fi

timing_enter identify
timing_enter start_nvmf_tgt

$NVMF_APP -c $testdir/../nvmf.conf &
nvmfpid=$!

trap "killprocess $nvmfpid; exit 1" SIGINT SIGTERM EXIT

waitforlisten $nvmfpid ${RPC_PORT}
timing_exit start_nvmf_tgt

bdevs="$bdevs $($rpc_py construct_malloc_bdev $MALLOC_BDEV_SIZE $MALLOC_BLOCK_SIZE)"

$rpc_py construct_nvmf_subsystem nqn.2016-06.io.spdk:cnode1 "trtype:RDMA traddr:$NVMF_FIRST_TARGET_IP trsvcid:4420" '' -s SPDK00000000000001 -n "$bdevs"

$rootdir/examples/nvme/identify/identify -r "\
        trtype:RDMA \
        adrfam:IPv4 \
        traddr:$NVMF_FIRST_TARGET_IP \
        trsvcid:$NVMF_PORT \
        subnqn:nqn.2014-08.org.nvmexpress.discovery" -t all
$rootdir/examples/nvme/identify/identify -r "\
        trtype:RDMA \
        adrfam:IPv4 \
        traddr:$NVMF_FIRST_TARGET_IP \
        trsvcid:$NVMF_PORT \
        subnqn:nqn.2016-06.io.spdk:cnode1" -t all
sync
$rpc_py delete_nvmf_subsystem nqn.2016-06.io.spdk:cnode1

trap - SIGINT SIGTERM EXIT

killprocess $nvmfpid
timing_exit identify
