#
#  BSD LICENSE
#
#  Copyright (c) Intel Corporation.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in
#      the documentation and/or other materials provided with the
#      distribution.
#    * Neither the name of Intel Corporation nor the names of its
#      contributors may be used to endorse or promote products derived
#      from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

COMMON_DIR := $(abspath $(CURDIR)/../../../../common/src/user)
LWIP_DIR := $(abspath $(CURDIR)/../../../../lwip)
PROCSTAT_DIR := $(abspath $(CURDIR)/../../../../procstat)
PROCSTAT_LIB := /users/sagi/workspace2/build/rel/procstat/29a58018d233
DPDK_DIR := /users/sagi/workspace2/build/rel/dpdk-sdk/61310895fa41
SPDK_ROOT_DIR := $(abspath $(CURDIR)/../../..)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

LWIP_SRC := $(LWIP_DIR)/src/core/def.c \
	$(LWIP_DIR)/src/core/init.c \
	$(LWIP_DIR)/src/core/mem.c \
	$(LWIP_DIR)/src/core/stats.c \
	$(LWIP_DIR)/src/core/memp.c \
	$(LWIP_DIR)/src/core/netif.c \
	$(LWIP_DIR)/src/core/pbuf.c \
	$(LWIP_DIR)/src/core/raw.c \
	$(LWIP_DIR)/src/core/ip.c \
	$(LWIP_DIR)/src/core/tcp.c \
	$(LWIP_DIR)/src/core/tcp_out.c \
	$(LWIP_DIR)/src/core/tcp_in.c \
	$(LWIP_DIR)/src/core/ipv4/icmp.c \
	$(LWIP_DIR)/src/core/inet_chksum.c \
	$(LWIP_DIR)/src/core/ipv4/ip4.c \
	$(LWIP_DIR)/src/core/ipv4/ip4_addr.c \
	$(LWIP_DIR)/src/core/ipv4/ip4_frag.c \
	$(LWIP_DIR)/src/core/timeouts.c \
	$(LWIP_DIR)/src/core/udp.c \
	$(LWIP_DIR)/src/core/ipv4/etharp.c\
	$(LWIP_DIR)/src/netif/ethernet.c\
	$(LWIP_DIR)/src/api/err.c\
	$(LWIP_DIR)/src/dpdk/network.c\
	$(LWIP_DIR)/src/dpdk/lsc.c\
	$(LWIP_DIR)/src/dpdk/net_trace.c\
	$(LWIP_DIR)/src/lb/lwip_stats.c\
	$(LWIP_DIR)/src/lb/tcp.c\
	$(LWIP_DIR)/src/lb/arch/sys_arch.c

LIBNAME = sock_lb
C_SRCS = lb.c stats.c $(LWIP_SRC)

LOCAL_SYS_LIBS += -l$(PROCSTAT_LIB)/lib -l$(DPDK_DIR)/lib
include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
COMMON_CFLAGS += -I$(DPDK_DIR)/include/dpdk -I$(LWIP_DIR)/src/include -I$(LWIP_DIR)/src -I$(LWIP_DIR)/src/lb -I$(LWIP_DIR)/src/dpdk -I$(COMMON_DIR)/dpdk/include -I$(COMMON_DIR)/common/include -I$(PROCSTAT_DIR)/src
