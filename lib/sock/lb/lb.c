/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/sock.h"
#include "spdk_internal/sock.h"
#include "spdk/net.h"

#include <rte_common.h>
#include <rte_eal.h>
#include "lwip/init.h"
#include "network.h"
#include "rx_buffer.h"
#include "procstat.h"

#define MAX_TMPBUF 1024
#define PORTNUMLEN 32

struct spdk_lb_sock {
	struct spdk_sock	base;
	int			fd;
};

struct spdk_lb_sock_group_impl {
	struct spdk_sock_group_impl	base;
	int				fd;
};

#define __lb_sock(sock) (struct spdk_lb_sock *)sock
#define __lb_group_impl(group) (struct spdk_lb_sock_group_impl *)group

struct procstat_context *procstat_ctx;

static int
spdk_lb_sock_getaddr(struct spdk_sock *_sock, char *saddr, int slen, uint16_t *sport,
			char *caddr, int clen, uint16_t *cport)
{
	return 0;
}

static struct spdk_sock *
spdk_lb_sock_listen(const char *ip, int port)
{
	return NULL;
}

static struct spdk_sock *
spdk_lb_sock_connect(const char *ip, int port)
{
	return NULL;
}

static struct spdk_sock *
spdk_lb_sock_accept(struct spdk_sock *_sock)
{
	return NULL;
}

static int
spdk_lb_sock_close(struct spdk_sock *_sock)
{
	return 0;
}

static ssize_t
spdk_lb_sock_recv(struct spdk_sock *_sock, void *buf, size_t len)
{
	return len;
}

static ssize_t
spdk_lb_sock_readv(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	return 0;
}

static ssize_t
spdk_lb_sock_writev(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	return 0;
}

static int
spdk_lb_sock_set_recvlowat(struct spdk_sock *_sock, int nbytes)
{
	return 0;
}

static int
spdk_lb_sock_set_recvbuf(struct spdk_sock *_sock, int sz)
{
	return 0;
}

static int
spdk_lb_sock_set_sendbuf(struct spdk_sock *_sock, int sz)
{
	return 0;
}

static bool
spdk_lb_sock_is_ipv6(struct spdk_sock *_sock)
{
	return false;
}

static bool
spdk_lb_sock_is_ipv4(struct spdk_sock *_sock)
{
	return true;
}

static struct spdk_sock_group_impl *
spdk_lb_sock_group_impl_create(void)
{
	return NULL;
}

static int
spdk_lb_sock_group_impl_add_sock(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	return 0;
}

static int
spdk_lb_sock_group_impl_remove_sock(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	return 0;
}

static int
spdk_lb_sock_group_impl_poll(struct spdk_sock_group_impl *_group, int max_events,
				struct spdk_sock **socks)
{
	return 0;
}

static int
spdk_lb_sock_group_impl_close(struct spdk_sock_group_impl *_group)
{
	return 0;
}

static struct spdk_net_impl g_lb_net_impl = {
	.name		= "lb",
	.getaddr	= spdk_lb_sock_getaddr,
	.connect	= spdk_lb_sock_connect,
	.listen		= spdk_lb_sock_listen,
	.accept		= spdk_lb_sock_accept,
	.close		= spdk_lb_sock_close,
	.recv		= spdk_lb_sock_recv,
	.readv		= spdk_lb_sock_readv,
	.writev		= spdk_lb_sock_writev,
	.set_recvlowat	= spdk_lb_sock_set_recvlowat,
	.set_recvbuf	= spdk_lb_sock_set_recvbuf,
	.set_sendbuf	= spdk_lb_sock_set_sendbuf,
	.is_ipv6	= spdk_lb_sock_is_ipv6,
	.is_ipv4	= spdk_lb_sock_is_ipv4,
	.group_impl_create	= spdk_lb_sock_group_impl_create,
	.group_impl_add_sock	= spdk_lb_sock_group_impl_add_sock,
	.group_impl_remove_sock = spdk_lb_sock_group_impl_remove_sock,
	.group_impl_poll	= spdk_lb_sock_group_impl_poll,
	.group_impl_close	= spdk_lb_sock_group_impl_close,
};

SPDK_NET_IMPL_REGISTER(lb, &g_lb_net_impl);

#define NUM_MBUFS_INCOMING_PER_QUEUE 1024
int spdk_sock_lb_alloc_netpools(struct procstat_item *parent,
		struct procstat_context *procstat_ctx)
{
	unsigned rx_size = NUM_MBUFS_INCOMING_PER_QUEUE * DEFAULT_NUM_HW_PORTS;
	struct rte_mempool *rx_pool;
	char name[] = "rx_pool_NN";
	int c, ret;

	RTE_LCORE_FOREACH(c) {
		snprintf(name + sizeof(name) - 3, 3, "%d", c);
		rx_pool = rte_pktmbuf_pool_create_by_ops(name, rx_size,
			RTE_MEMPOOL_CACHE_MAX_SIZE, sizeof(struct rx_buffer),
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id(),
			"ring_sp_sc");
		if (!rx_pool) {
			SPDK_ERRLOG("Failed to alloc rx_pool");
			return -ENOMEM;
		}

		rte_mempool_obj_iter(rx_pool, rte_pktmbuf_init, 0);
		rte_mempool_obj_iter(rx_pool, net_rxbuf_ctor, 0);
		rx_pools[c] = rx_pool;

		ret = lwip_register_pool_stats(rx_pool, name, parent,
					procstat_ctx);
		ASSERT(ret == 0);
		SPDK_ERRLOG("Allocated rx pool[%d]: %p", c, rx_pool);
	}

	return 0;
}

static void
spdk_lb_net_framework_init(void)
{
	const char* ip = getenv("LB_IP");
	const char* port = getenv("LB_PORT");
	const char* mount = getenv("LB_MOUNT");
	int nr_cores = rte_lcore_count();

	SPDK_ERRLOG("ip: %s port: %s\n", ip, port);

	ASSERT(nr_cores > 0);
	procstat_ctx = stats_create(mount);
	if (!procstat_ctx) {
		SPDK_ERRLOG("Failed to initialize stats\n");
		return;
	}

	lwip_init(nr_cores, rte_socket_id(), lwip_pcb_private_size());
	pools_dir = procstat_create_directory(procstat_ctx, NULL, "pools");
	ASSERT(pools_dir);

	ret = lwip_register_internal_pools_stats(pools_dir);
	ASSERT(ret == 0);
}

static void
spdk_lb_net_framework_fini(void)
{
}

static struct spdk_net_framework g_lb_net_framework = {
	.name	= "lb",
	.init	= spdk_lb_net_framework_init,
	.fini	= spdk_lb_net_framework_fini,
};

SPDK_NET_FRAMEWORK_REGISTER(lb, &g_lb_net_framework);
