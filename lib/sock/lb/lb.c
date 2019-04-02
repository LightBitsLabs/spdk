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
#include "spdk/thread.h"

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include "lwip/init.h"
#include "network.h"
#include "rx_buffer.h"
#include "procstat.h"
#include "stats.h"

#include <rte_log.h>
#include "lb/log.h"
#include "lb/err.h"
#include "lb/lwip_stats.h"

#define RTE_LOGTYPE_NET			RTE_LOGTYPE_USER1

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
struct procstat_item *pools, *hwport, *net_qp;
struct rte_mempool *rx_pools[RTE_MAX_LCORE];

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

static int
lbnet_poll(void *arg)
{
	struct net_device *dev = arg;
	struct qp *qp = LCORE_NET_IFACE(dev).qp;
	int ret = 0;

	ret += poll_rx_queue(qp);
	ret += poll_tx_queue(qp);

	return 0;
}

#define NUM_MBUFS_INCOMING_PER_QUEUE	1024 * 4
static int spdk_sock_lb_alloc_netpools(struct procstat_item *parent,
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

		SPDK_ERRLOG("Allocated rx pool[%d]: %p\n", c, rx_pool);
	}

	return 0;
}

#define TX_RING_SIZE 1024
#define RX_RING_SIZE 1024
static struct net_device *app_create_eth_dev(uint8_t nr_cores)
{
	struct net_device *dev;
	uint16_t nr_rx_queues = nr_cores;
	uint16_t nr_tx_queues = nr_cores;
	int c, idx = 0, p, d = 0;

	RTE_ETH_FOREACH_DEV(p) {
                SPDK_ERRLOG("port %d is available\n", p);
                d++;
        }
        SPDK_ERRLOG("%d ports\n", d);

	dev = create_net_device(nr_rx_queues, nr_tx_queues, 1500, nr_cores);
	if (IS_ERR(dev)) {
		SPDK_ERRLOG("Failed to create net device\n");
		return NULL;
	}

	RTE_LCORE_FOREACH(c) {
		struct qp *qp;

		dev->net_ifaces[c].rx_buffers = rx_pools[c];
		qp = create_net_qp(dev, c, idx, idx, TX_RING_SIZE, RX_RING_SIZE);
		if (unlikely(IS_ERR(qp))) {
			SPDK_ERRLOG("Failed to create net QPs");
			goto destroy_qps;
		}

		ASSERT(lwip_register_lcore_qp_stats(net_qp, dev, qp) == 0);

		idx++;
	}

	return dev;

destroy_qps:
	RTE_LCORE_FOREACH(c) {
		struct qp *qp = dev->net_ifaces[c].qp;

		net_destroy_qp(qp);
		if (--idx < 0)
			break;
	}

	net_device_destroy(dev);
	return NULL;
}

static int app_config_net_iface(struct net_device *net_dev,
	const char *ip, const char *netmask, const char *default_gw)
{
	struct l3_config l3_config;

	memset(&l3_config, 0, sizeof(l3_config));

	if (!inet_aton(ip, (struct in_addr *)&l3_config.ip)) {
		SPDK_ERRLOG("Failed to init ip: %s",
			    ip);
		return -EINVAL;
	}

	if (!inet_aton(default_gw, (struct in_addr *)&l3_config.gw)) {
		SPDK_ERRLOG("Failed to init gw: %s", default_gw);
		return -EINVAL;
	}

	if (!inet_aton(netmask, (struct in_addr *)&l3_config.netmask)) {
		SPDK_ERRLOG("Failed to init netmask");
		return -EINVAL;
	}

	return start_net_device(net_dev, &l3_config);
}

static void register_pollers(struct net_device *dev)
{
	int c;

	RTE_LCORE_FOREACH(c) {
		spdk_poller_register(lbnet_poll, dev, 0);
	}
}

static void
spdk_lb_net_framework_init(void)
{
	struct net_device *dev;
	const char* ip = getenv("LB_IP");
	const char* nm = getenv("LB_NETMASK");
	const char* gw = getenv("LB_GATEWAY");
	int ret, nr_cores = rte_lcore_count();

	SPDK_ERRLOG("ip: %s nm: %s, gw %s\n", ip, nm, gw);

	ASSERT(nr_cores > 0);

	lwip_init(nr_cores, rte_socket_id(), 0 /* ? */);
	rte_timer_subsystem_init();

	procstat_ctx = stats_create("/tmp/spdkstats");
	ASSERT(procstat_ctx);

	pools = procstat_create_directory(procstat_ctx, NULL, "pools");
	ASSERT(pools);

	net_qp = procstat_create_directory(procstat_ctx, NULL, "net_qp");
	ASSERT(net_qp);

	spdk_sock_lb_alloc_netpools(pools, procstat_ctx);

	dev = app_create_eth_dev(nr_cores);
	if (!dev)
		PANIC("Failed to init ETH device");

	ret = app_config_net_iface(dev, ip, nm, gw);
	if (ret)
		PANIC("Failed to configure lwip");

	ret = lwip_register_internal_pools_stats(pools);
	ASSERT(ret == 0);

	hwport = procstat_create_directory(procstat_ctx, NULL, "hwport");
	ASSERT(hwport);

	ret = lwip_register_hwport_stats(hwport, dev, rte_get_tsc_hz() / 10);
	ASSERT(ret == 0);

	ret = lwip_register_hw_extended_stats(hwport, dev);
	ASSERT(ret == 0);

	register_pollers(dev);
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
