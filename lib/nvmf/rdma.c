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

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>

#include "nvmf_internal.h"
#include "request.h"
#include "ctrlr.h"
#include "subsystem.h"
#include "transport.h"

#include "spdk/assert.h"
#include "spdk/nvmf.h"
#include "spdk/nvmf_spec.h"
#include "spdk/string.h"
#include "spdk/trace.h"
#include "spdk/util.h"
#include "spdk/likely.h"

#include "spdk_internal/log.h"

/*
 RDMA Connection Resouce Defaults
 */
#define NVMF_DEFAULT_TX_SGE		1
#define NVMF_DEFAULT_RX_SGE		2

/* This structure holds commands as they are received off the wire.
 * It must be dynamically paired with a full request object
 * (spdk_nvmf_rdma_request) to service a request. It is separate
 * from the request because RDMA does not appear to order
 * completions, so occasionally we'll get a new incoming
 * command when there aren't any free request objects.
 */
struct spdk_nvmf_rdma_recv {
	struct ibv_recv_wr		wr;
	struct ibv_sge			sgl[NVMF_DEFAULT_RX_SGE];

	/* In-capsule data buffer */
	uint8_t				*buf;

	TAILQ_ENTRY(spdk_nvmf_rdma_recv) link;
};

struct spdk_nvmf_rdma_request {
	struct spdk_nvmf_request		req;
	bool					data_from_pool;

	struct spdk_nvmf_rdma_recv		*recv;

	struct {
		struct	ibv_send_wr		wr;
		struct	ibv_sge			sgl[NVMF_DEFAULT_TX_SGE];
	} rsp;

	struct {
		struct ibv_send_wr		wr;
		struct ibv_sge			sgl[NVMF_DEFAULT_TX_SGE];
	} data;

	TAILQ_ENTRY(spdk_nvmf_rdma_request)	link;
};

struct spdk_nvmf_rdma_qpair {
	struct spdk_nvmf_qpair			qpair;

	struct spdk_nvmf_rdma_port		*port;

	struct rdma_cm_id			*cm_id;
	struct ibv_cq				*cq;

	/* The maximum number of I/O outstanding on this connection at one time */
	uint16_t				max_queue_depth;

	/* The maximum number of active RDMA READ and WRITE operations at one time */
	uint16_t				max_rw_depth;

	/* The current number of I/O outstanding on this connection. This number
	 * includes all I/O from the time the capsule is first received until it is
	 * completed.
	 */
	uint16_t				cur_queue_depth;

	/* The number of RDMA READ and WRITE requests that are outstanding */
	uint16_t				cur_rdma_rw_depth;

	/* Receives that are waiting for a request object */
	TAILQ_HEAD(, spdk_nvmf_rdma_recv)	incoming_queue;

	/* Requests that are not in use */
	TAILQ_HEAD(, spdk_nvmf_rdma_request)	free_queue;

	/* Requests that are waiting to obtain a data buffer */
	TAILQ_HEAD(, spdk_nvmf_rdma_request)	pending_data_buf_queue;

	/* Requests that are waiting to perform an RDMA READ or WRITE */
	TAILQ_HEAD(, spdk_nvmf_rdma_request)	pending_rdma_rw_queue;

	/* Array of size "max_queue_depth" containing RDMA requests. */
	struct spdk_nvmf_rdma_request		*reqs;

	/* Array of size "max_queue_depth" containing RDMA recvs. */
	struct spdk_nvmf_rdma_recv		*recvs;

	/* Array of size "max_queue_depth" containing 64 byte capsules
	 * used for receive.
	 */
	union nvmf_h2c_msg			*cmds;
	struct ibv_mr				*cmds_mr;

	/* Array of size "max_queue_depth" containing 16 byte completions
	 * to be sent back to the user.
	 */
	union nvmf_c2h_msg			*cpls;
	struct ibv_mr				*cpls_mr;

	/* Array of size "max_queue_depth * InCapsuleDataSize" containing
	 * buffers to be used for in capsule data.
	 */
	void					*bufs;
	struct ibv_mr				*bufs_mr;

	TAILQ_ENTRY(spdk_nvmf_rdma_qpair)	link;
};

/* List of RDMA connections that have not yet received a CONNECT capsule */
static TAILQ_HEAD(, spdk_nvmf_rdma_qpair) g_pending_conns = TAILQ_HEAD_INITIALIZER(g_pending_conns);

struct spdk_nvmf_rdma_poll_group {
	struct spdk_nvmf_poll_group		group;

	struct spdk_nvmf_rdma_device		*device;
};

/* Assuming rdma_cm uses just one protection domain per ibv_context. */
struct spdk_nvmf_rdma_device {
	struct ibv_device_attr			attr;
	struct ibv_context			*context;

	struct spdk_mem_map			*map;
	struct ibv_pd				*pd;

	TAILQ_ENTRY(spdk_nvmf_rdma_device)	link;
};

struct spdk_nvmf_rdma_port {
	struct spdk_nvme_transport_id		trid;
	struct rdma_cm_id			*id;
	struct spdk_nvmf_rdma_device		*device;
	uint32_t				ref;
	TAILQ_ENTRY(spdk_nvmf_rdma_port)	link;
};

struct spdk_nvmf_rdma_transport {
	struct spdk_nvmf_transport	transport;

	struct rdma_event_channel	*event_channel;

	struct spdk_mempool		*data_buf_pool;

	pthread_mutex_t 		lock;

	uint16_t 			max_queue_depth;
	uint32_t 			max_io_size;
	uint32_t 			in_capsule_data_size;

	TAILQ_HEAD(, spdk_nvmf_rdma_device)	devices;
	TAILQ_HEAD(, spdk_nvmf_rdma_port)	ports;
};

static void
spdk_nvmf_rdma_qpair_destroy(struct spdk_nvmf_rdma_qpair *rdma_qpair)
{
	if (rdma_qpair->cmds_mr) {
		ibv_dereg_mr(rdma_qpair->cmds_mr);
	}

	if (rdma_qpair->cpls_mr) {
		ibv_dereg_mr(rdma_qpair->cpls_mr);
	}

	if (rdma_qpair->bufs_mr) {
		ibv_dereg_mr(rdma_qpair->bufs_mr);
	}

	if (rdma_qpair->cm_id) {
		rdma_destroy_qp(rdma_qpair->cm_id);
		rdma_destroy_id(rdma_qpair->cm_id);
	}

	if (rdma_qpair->cq) {
		ibv_destroy_cq(rdma_qpair->cq);
	}

	/* Free all memory */
	spdk_dma_free(rdma_qpair->cmds);
	spdk_dma_free(rdma_qpair->cpls);
	spdk_dma_free(rdma_qpair->bufs);
	free(rdma_qpair->reqs);
	free(rdma_qpair);
}

static struct spdk_nvmf_rdma_qpair *
spdk_nvmf_rdma_qpair_create(struct spdk_nvmf_transport *transport,
			    struct spdk_nvmf_rdma_port *port,
			    struct rdma_cm_id *id,
			    uint16_t max_queue_depth, uint16_t max_rw_depth, uint32_t subsystem_id)
{
	struct spdk_nvmf_rdma_transport *rtransport;
	struct spdk_nvmf_rdma_qpair	*rdma_qpair;
	struct spdk_nvmf_qpair		*qpair;
	int				rc, i;
	struct ibv_qp_init_attr		attr;
	struct spdk_nvmf_rdma_recv	*rdma_recv;
	struct spdk_nvmf_rdma_request	*rdma_req;
	char buf[64];

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_rdma_transport, transport);

	rdma_qpair = calloc(1, sizeof(struct spdk_nvmf_rdma_qpair));
	if (rdma_qpair == NULL) {
		SPDK_ERRLOG("Could not allocate new connection.\n");
		return NULL;
	}

	rdma_qpair->port = port;
	rdma_qpair->max_queue_depth = max_queue_depth;
	rdma_qpair->max_rw_depth = max_rw_depth;
	TAILQ_INIT(&rdma_qpair->incoming_queue);
	TAILQ_INIT(&rdma_qpair->free_queue);
	TAILQ_INIT(&rdma_qpair->pending_data_buf_queue);
	TAILQ_INIT(&rdma_qpair->pending_rdma_rw_queue);

	rdma_qpair->cq = ibv_create_cq(id->verbs, max_queue_depth * 3, rdma_qpair, NULL, 0);
	if (!rdma_qpair->cq) {
		spdk_strerror_r(errno, buf, sizeof(buf));
		SPDK_ERRLOG("Unable to create completion queue\n");
		SPDK_ERRLOG("Errno %d: %s\n", errno, buf);
		rdma_destroy_id(id);
		spdk_nvmf_rdma_qpair_destroy(rdma_qpair);
		return NULL;
	}

	memset(&attr, 0, sizeof(struct ibv_qp_init_attr));
	attr.qp_type		= IBV_QPT_RC;
	attr.send_cq		= rdma_qpair->cq;
	attr.recv_cq		= rdma_qpair->cq;
	attr.cap.max_send_wr	= max_queue_depth * 2; /* SEND, READ, and WRITE operations */
	attr.cap.max_recv_wr	= max_queue_depth; /* RECV operations */
	attr.cap.max_send_sge	= NVMF_DEFAULT_TX_SGE;
	attr.cap.max_recv_sge	= NVMF_DEFAULT_RX_SGE;

	rc = rdma_create_qp(id, NULL, &attr);
	if (rc) {
		spdk_strerror_r(errno, buf, sizeof(buf));
		SPDK_ERRLOG("rdma_create_qp failed\n");
		SPDK_ERRLOG("Errno %d: %s\n", errno, buf);
		rdma_destroy_id(id);
		spdk_nvmf_rdma_qpair_destroy(rdma_qpair);
		return NULL;
	}

	qpair = &rdma_qpair->qpair;
	qpair->transport = transport;
	id->context = qpair;
	rdma_qpair->cm_id = id;

	SPDK_TRACELOG(SPDK_TRACE_RDMA, "New RDMA Connection: %p\n", qpair);

	rdma_qpair->reqs = calloc(max_queue_depth, sizeof(*rdma_qpair->reqs));
	rdma_qpair->recvs = calloc(max_queue_depth, sizeof(*rdma_qpair->recvs));
	rdma_qpair->cmds = spdk_dma_zmalloc(max_queue_depth * sizeof(*rdma_qpair->cmds),
					    0x1000, NULL);
	rdma_qpair->cpls = spdk_dma_zmalloc(max_queue_depth * sizeof(*rdma_qpair->cpls),
					    0x1000, NULL);
	rdma_qpair->bufs = spdk_dma_zmalloc(max_queue_depth * rtransport->in_capsule_data_size,
					    0x1000, NULL);
	if (!rdma_qpair->reqs || !rdma_qpair->recvs || !rdma_qpair->cmds ||
	    !rdma_qpair->cpls || !rdma_qpair->bufs) {
		SPDK_ERRLOG("Unable to allocate sufficient memory for RDMA queue.\n");
		spdk_nvmf_rdma_qpair_destroy(rdma_qpair);
		return NULL;
	}

	rdma_qpair->cmds_mr = ibv_reg_mr(id->pd, rdma_qpair->cmds,
					 max_queue_depth * sizeof(*rdma_qpair->cmds),
					 IBV_ACCESS_LOCAL_WRITE);
	rdma_qpair->cpls_mr = ibv_reg_mr(id->pd, rdma_qpair->cpls,
					 max_queue_depth * sizeof(*rdma_qpair->cpls),
					 0);
	rdma_qpair->bufs_mr = ibv_reg_mr(id->pd, rdma_qpair->bufs,
					 max_queue_depth * rtransport->in_capsule_data_size,
					 IBV_ACCESS_LOCAL_WRITE |
					 IBV_ACCESS_REMOTE_WRITE);
	if (!rdma_qpair->cmds_mr || !rdma_qpair->cpls_mr || !rdma_qpair->bufs_mr) {
		SPDK_ERRLOG("Unable to register required memory for RDMA queue.\n");
		spdk_nvmf_rdma_qpair_destroy(rdma_qpair);
		return NULL;
	}
	SPDK_TRACELOG(SPDK_TRACE_RDMA, "Command Array: %p Length: %lx LKey: %x\n",
		      rdma_qpair->cmds, max_queue_depth * sizeof(*rdma_qpair->cmds), rdma_qpair->cmds_mr->lkey);
	SPDK_TRACELOG(SPDK_TRACE_RDMA, "Completion Array: %p Length: %lx LKey: %x\n",
		      rdma_qpair->cpls, max_queue_depth * sizeof(*rdma_qpair->cpls), rdma_qpair->cpls_mr->lkey);
	SPDK_TRACELOG(SPDK_TRACE_RDMA, "In Capsule Data Array: %p Length: %x LKey: %x\n",
		      rdma_qpair->bufs, max_queue_depth * rtransport->in_capsule_data_size, rdma_qpair->bufs_mr->lkey);

	for (i = 0; i < max_queue_depth; i++) {
		struct ibv_recv_wr *bad_wr = NULL;

		rdma_recv = &rdma_qpair->recvs[i];

		/* Set up memory to receive commands */
		rdma_recv->buf = (void *)((uintptr_t)rdma_qpair->bufs + (i * rtransport->in_capsule_data_size));

		rdma_recv->sgl[0].addr = (uintptr_t)&rdma_qpair->cmds[i];
		rdma_recv->sgl[0].length = sizeof(rdma_qpair->cmds[i]);
		rdma_recv->sgl[0].lkey = rdma_qpair->cmds_mr->lkey;

		rdma_recv->sgl[1].addr = (uintptr_t)rdma_recv->buf;
		rdma_recv->sgl[1].length = rtransport->in_capsule_data_size;
		rdma_recv->sgl[1].lkey = rdma_qpair->bufs_mr->lkey;

		rdma_recv->wr.wr_id = (uintptr_t)rdma_recv;
		rdma_recv->wr.sg_list = rdma_recv->sgl;
		rdma_recv->wr.num_sge = SPDK_COUNTOF(rdma_recv->sgl);

		rc = ibv_post_recv(rdma_qpair->cm_id->qp, &rdma_recv->wr, &bad_wr);
		if (rc) {
			SPDK_ERRLOG("Unable to post capsule for RDMA RECV\n");
			spdk_nvmf_rdma_qpair_destroy(rdma_qpair);
			return NULL;
		}
	}

	for (i = 0; i < max_queue_depth; i++) {
		rdma_req = &rdma_qpair->reqs[i];

		rdma_req->req.qpair = &rdma_qpair->qpair;
		rdma_req->req.cmd = NULL;

		/* Set up memory to send responses */
		rdma_req->req.rsp = &rdma_qpair->cpls[i];

		rdma_req->rsp.sgl[0].addr = (uintptr_t)&rdma_qpair->cpls[i];
		rdma_req->rsp.sgl[0].length = sizeof(rdma_qpair->cpls[i]);
		rdma_req->rsp.sgl[0].lkey = rdma_qpair->cpls_mr->lkey;

		rdma_req->rsp.wr.wr_id = (uintptr_t)rdma_req;
		rdma_req->rsp.wr.next = NULL;
		rdma_req->rsp.wr.opcode = IBV_WR_SEND;
		rdma_req->rsp.wr.send_flags = IBV_SEND_SIGNALED;
		rdma_req->rsp.wr.sg_list = rdma_req->rsp.sgl;
		rdma_req->rsp.wr.num_sge = SPDK_COUNTOF(rdma_req->rsp.sgl);

		/* Set up memory for data buffers */
		rdma_req->data.wr.wr_id = (uint64_t)rdma_req;
		rdma_req->data.wr.next = NULL;
		rdma_req->data.wr.send_flags = IBV_SEND_SIGNALED;
		rdma_req->data.wr.sg_list = rdma_req->data.sgl;
		rdma_req->data.wr.num_sge = SPDK_COUNTOF(rdma_req->data.sgl);

		TAILQ_INSERT_TAIL(&rdma_qpair->free_queue, rdma_req, link);
	}

	return rdma_qpair;
}

static int
request_transfer_in(struct spdk_nvmf_request *req)
{
	int				rc;
	struct spdk_nvmf_rdma_request	*rdma_req;
	struct spdk_nvmf_qpair 		*qpair;
	struct spdk_nvmf_rdma_qpair 	*rdma_qpair;
	struct ibv_send_wr		*bad_wr = NULL;

	qpair = req->qpair;
	rdma_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_rdma_request, req);
	rdma_qpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair);

	assert(req->xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER);

	rdma_qpair->cur_rdma_rw_depth++;

	SPDK_TRACELOG(SPDK_TRACE_RDMA, "RDMA READ POSTED. Request: %p Connection: %p\n", req, qpair);
	spdk_trace_record(TRACE_RDMA_READ_START, 0, 0, (uintptr_t)req, 0);

	rdma_req->data.wr.opcode = IBV_WR_RDMA_READ;
	rdma_req->data.wr.next = NULL;
	rc = ibv_post_send(rdma_qpair->cm_id->qp, &rdma_req->data.wr, &bad_wr);
	if (rc) {
		SPDK_ERRLOG("Unable to transfer data from host to target\n");
		return -1;
	}

	return 0;
}

static int
request_transfer_out(struct spdk_nvmf_request *req)
{
	int 				rc;
	struct spdk_nvmf_rdma_request	*rdma_req;
	struct spdk_nvmf_qpair		*qpair;
	struct spdk_nvmf_rdma_qpair 	*rdma_qpair;
	struct spdk_nvme_cpl		*rsp;
	struct ibv_recv_wr		*bad_recv_wr = NULL;
	struct ibv_send_wr		*send_wr, *bad_send_wr = NULL;

	qpair = req->qpair;
	rsp = &req->rsp->nvme_cpl;
	rdma_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_rdma_request, req);
	rdma_qpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair);

	/* Advance our sq_head pointer */
	if (qpair->sq_head == qpair->sq_head_max) {
		qpair->sq_head = 0;
	} else {
		qpair->sq_head++;
	}
	rsp->sqhd = qpair->sq_head;

	/* Post the capsule to the recv buffer */
	assert(rdma_req->recv != NULL);
	SPDK_TRACELOG(SPDK_TRACE_RDMA, "RDMA RECV POSTED. Recv: %p Connection: %p\n", rdma_req->recv,
		      rdma_qpair);
	rc = ibv_post_recv(rdma_qpair->cm_id->qp, &rdma_req->recv->wr, &bad_recv_wr);
	if (rc) {
		SPDK_ERRLOG("Unable to re-post rx descriptor\n");
		return rc;
	}
	rdma_req->recv = NULL;

	/* Build the response which consists of an optional
	 * RDMA WRITE to transfer data, plus an RDMA SEND
	 * containing the response.
	 */
	send_wr = &rdma_req->rsp.wr;

	if (rsp->status.sc == SPDK_NVME_SC_SUCCESS &&
	    req->xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
		SPDK_TRACELOG(SPDK_TRACE_RDMA, "RDMA WRITE POSTED. Request: %p Connection: %p\n", req, qpair);
		spdk_trace_record(TRACE_RDMA_WRITE_START, 0, 0, (uintptr_t)req, 0);

		rdma_qpair->cur_rdma_rw_depth++;
		rdma_req->data.wr.opcode = IBV_WR_RDMA_WRITE;

		rdma_req->data.wr.next = send_wr;
		send_wr = &rdma_req->data.wr;
	}

	SPDK_TRACELOG(SPDK_TRACE_RDMA, "RDMA SEND POSTED. Request: %p Connection: %p\n", req, qpair);
	spdk_trace_record(TRACE_NVMF_IO_COMPLETE, 0, 0, (uintptr_t)req, 0);

	/* Send the completion */
	rc = ibv_post_send(rdma_qpair->cm_id->qp, send_wr, &bad_send_wr);
	if (rc) {
		SPDK_ERRLOG("Unable to send response capsule\n");
	}

	return rc;
}

static int
spdk_nvmf_rdma_request_transfer_data(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_rdma_request	*rdma_req;
	struct spdk_nvmf_qpair		*qpair;
	struct spdk_nvmf_rdma_qpair	*rdma_qpair;

	qpair = req->qpair;
	rdma_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_rdma_request, req);
	rdma_qpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair);

	if (req->xfer == SPDK_NVME_DATA_NONE) {
		/* If no data transfer, this can bypass the queue */
		return request_transfer_out(req);
	}

	if (rdma_qpair->cur_rdma_rw_depth < rdma_qpair->max_rw_depth) {
		if (req->xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
			return request_transfer_out(req);
		} else if (req->xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
			return request_transfer_in(req);
		}
	} else {
		TAILQ_INSERT_TAIL(&rdma_qpair->pending_rdma_rw_queue, rdma_req, link);
	}

	return 0;
}

static int
nvmf_rdma_connect(struct spdk_nvmf_transport *transport, struct rdma_cm_event *event)
{
	struct spdk_nvmf_rdma_transport *rtransport;
	struct spdk_nvmf_rdma_qpair	*rdma_qpair = NULL;
	struct spdk_nvmf_rdma_port 	*port;
	struct rdma_conn_param		*rdma_param = NULL;
	struct rdma_conn_param		ctrlr_event_data;
	const struct spdk_nvmf_rdma_request_private_data *private_data = NULL;
	struct spdk_nvmf_rdma_accept_private_data accept_data;
	uint16_t			sts = 0;
	uint16_t			max_queue_depth;
	uint16_t			max_rw_depth;
	uint32_t			subsystem_id = 0;
	int 				rc;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_rdma_transport, transport);

	if (event->id == NULL) {
		SPDK_ERRLOG("connect request: missing cm_id\n");
		goto err0;
	}

	if (event->id->verbs == NULL) {
		SPDK_ERRLOG("connect request: missing cm_id ibv_context\n");
		goto err0;
	}

	rdma_param = &event->param.conn;
	if (rdma_param->private_data == NULL ||
	    rdma_param->private_data_len < sizeof(struct spdk_nvmf_rdma_request_private_data)) {
		SPDK_ERRLOG("connect request: no private data provided\n");
		goto err0;
	}
	private_data = rdma_param->private_data;

	SPDK_TRACELOG(SPDK_TRACE_RDMA, "Connect Recv on fabric intf name %s, dev_name %s\n",
		      event->id->verbs->device->name, event->id->verbs->device->dev_name);

	port = event->listen_id->context;
	SPDK_TRACELOG(SPDK_TRACE_RDMA, "Listen Id was %p with verbs %p. ListenAddr: %p\n",
		      event->listen_id, event->listen_id->verbs, port);

	/* Figure out the supported queue depth. This is a multi-step process
	 * that takes into account hardware maximums, host provided values,
	 * and our target's internal memory limits */

	SPDK_TRACELOG(SPDK_TRACE_RDMA, "Calculating Queue Depth\n");

	/* Start with the maximum queue depth allowed by the target */
	max_queue_depth = rtransport->max_queue_depth;
	max_rw_depth = rtransport->max_queue_depth;
	SPDK_TRACELOG(SPDK_TRACE_RDMA, "Target Max Queue Depth: %d\n", rtransport->max_queue_depth);

	/* Next check the local NIC's hardware limitations */
	SPDK_TRACELOG(SPDK_TRACE_RDMA,
		      "Local NIC Max Send/Recv Queue Depth: %d Max Read/Write Queue Depth: %d\n",
		      port->device->attr.max_qp_wr, port->device->attr.max_qp_rd_atom);
	max_queue_depth = spdk_min(max_queue_depth, port->device->attr.max_qp_wr);
	max_rw_depth = spdk_min(max_rw_depth, port->device->attr.max_qp_rd_atom);

	/* Next check the remote NIC's hardware limitations */
	SPDK_TRACELOG(SPDK_TRACE_RDMA,
		      "Host (Initiator) NIC Max Incoming RDMA R/W operations: %d Max Outgoing RDMA R/W operations: %d\n",
		      rdma_param->initiator_depth, rdma_param->responder_resources);
	if (rdma_param->initiator_depth > 0) {
		max_rw_depth = spdk_min(max_rw_depth, rdma_param->initiator_depth);
	}

	/* Finally check for the host software requested values, which are
	 * optional. */
	if (rdma_param->private_data != NULL &&
	    rdma_param->private_data_len >= sizeof(struct spdk_nvmf_rdma_request_private_data)) {
		SPDK_TRACELOG(SPDK_TRACE_RDMA, "Host Receive Queue Size: %d\n", private_data->hrqsize);
		SPDK_TRACELOG(SPDK_TRACE_RDMA, "Host Send Queue Size: %d\n", private_data->hsqsize);
		max_queue_depth = spdk_min(max_queue_depth, private_data->hrqsize);
		max_queue_depth = spdk_min(max_queue_depth, private_data->hsqsize + 1);
	}

	SPDK_TRACELOG(SPDK_TRACE_RDMA, "Final Negotiated Queue Depth: %d R/W Depth: %d\n",
		      max_queue_depth, max_rw_depth);

	/* Init the NVMf rdma transport connection */
	rdma_qpair = spdk_nvmf_rdma_qpair_create(transport, port, event->id, max_queue_depth,
			max_rw_depth, subsystem_id);
	if (rdma_qpair == NULL) {
		SPDK_ERRLOG("Error on nvmf connection creation\n");
		goto err1;
	}

	accept_data.recfmt = 0;
	accept_data.crqsize = max_queue_depth;
	ctrlr_event_data = *rdma_param;
	ctrlr_event_data.private_data = &accept_data;
	ctrlr_event_data.private_data_len = sizeof(accept_data);
	if (event->id->ps == RDMA_PS_TCP) {
		ctrlr_event_data.responder_resources = 0; /* We accept 0 reads from the host */
		ctrlr_event_data.initiator_depth = max_rw_depth;
	}

	rc = rdma_accept(event->id, &ctrlr_event_data);
	if (rc) {
		SPDK_ERRLOG("Error %d on rdma_accept\n", errno);
		goto err2;
	}
	SPDK_TRACELOG(SPDK_TRACE_RDMA, "Sent back the accept\n");

	/* Add this RDMA connection to the global list until a CONNECT capsule
	 * is received. */
	TAILQ_INSERT_TAIL(&g_pending_conns, rdma_qpair, link);

	return 0;

err2:
	spdk_nvmf_rdma_qpair_destroy(rdma_qpair);

err1: {
		struct spdk_nvmf_rdma_reject_private_data rej_data;

		rej_data.status.sc = sts;
		rdma_reject(event->id, &ctrlr_event_data, sizeof(rej_data));
	}
err0:
	return -1;
}

static int
nvmf_rdma_disconnect(struct rdma_cm_event *evt)
{
	struct spdk_nvmf_qpair		*qpair;
	struct spdk_nvmf_ctrlr		*ctrlr;
	struct spdk_nvmf_subsystem	*subsystem;
	struct spdk_nvmf_rdma_qpair 	*rdma_qpair;

	if (evt->id == NULL) {
		SPDK_ERRLOG("disconnect request: missing cm_id\n");
		return -1;
	}

	qpair = evt->id->context;
	if (qpair == NULL) {
		SPDK_ERRLOG("disconnect request: no active connection\n");
		return -1;
	}
	/* ack the disconnect event before rdma_destroy_id */
	rdma_ack_cm_event(evt);

	rdma_qpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair);

	ctrlr = qpair->ctrlr;
	if (ctrlr == NULL) {
		/* No ctrlr has been established yet. That means the qpair
		 * must be in the pending connections list. Remove it. */
		TAILQ_REMOVE(&g_pending_conns, rdma_qpair, link);
		spdk_nvmf_rdma_qpair_destroy(rdma_qpair);
		return 0;
	}

	subsystem = ctrlr->subsys;

	subsystem->disconnect_cb(subsystem->cb_ctx, qpair);

	return 0;
}

#ifdef DEBUG
static const char *CM_EVENT_STR[] = {
	"RDMA_CM_EVENT_ADDR_RESOLVED",
	"RDMA_CM_EVENT_ADDR_ERROR",
	"RDMA_CM_EVENT_ROUTE_RESOLVED",
	"RDMA_CM_EVENT_ROUTE_ERROR",
	"RDMA_CM_EVENT_CONNECT_REQUEST",
	"RDMA_CM_EVENT_CONNECT_RESPONSE",
	"RDMA_CM_EVENT_CONNECT_ERROR",
	"RDMA_CM_EVENT_UNREACHABLE",
	"RDMA_CM_EVENT_REJECTED",
	"RDMA_CM_EVENT_ESTABLISHED",
	"RDMA_CM_EVENT_DISCONNECTED",
	"RDMA_CM_EVENT_DEVICE_REMOVAL",
	"RDMA_CM_EVENT_MULTICAST_JOIN",
	"RDMA_CM_EVENT_MULTICAST_ERROR",
	"RDMA_CM_EVENT_ADDR_CHANGE",
	"RDMA_CM_EVENT_TIMEWAIT_EXIT"
};
#endif /* DEBUG */

typedef enum _spdk_nvmf_request_prep_type {
	SPDK_NVMF_REQUEST_PREP_ERROR = -1,
	SPDK_NVMF_REQUEST_PREP_READY = 0,
	SPDK_NVMF_REQUEST_PREP_PENDING_BUFFER = 1,
	SPDK_NVMF_REQUEST_PREP_PENDING_DATA = 2,
} spdk_nvmf_request_prep_type;

static int
spdk_nvmf_rdma_mem_notify(void *cb_ctx, struct spdk_mem_map *map,
			  enum spdk_mem_map_notify_action action,
			  void *vaddr, size_t size)
{
	struct spdk_nvmf_rdma_device *device = cb_ctx;
	struct ibv_pd *pd = device->pd;
	struct ibv_mr *mr;

	switch (action) {
	case SPDK_MEM_MAP_NOTIFY_REGISTER:
		mr = ibv_reg_mr(pd, vaddr, size,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE);
		if (mr == NULL) {
			SPDK_ERRLOG("ibv_reg_mr() failed\n");
			return -1;
		} else {
			spdk_mem_map_set_translation(map, (uint64_t)vaddr, size, (uint64_t)mr);
		}
		break;
	case SPDK_MEM_MAP_NOTIFY_UNREGISTER:
		mr = (struct ibv_mr *)spdk_mem_map_translate(map, (uint64_t)vaddr);
		spdk_mem_map_clear_translation(map, (uint64_t)vaddr, size);
		if (mr) {
			ibv_dereg_mr(mr);
		}
		break;
	}

	return 0;
}

typedef enum spdk_nvme_data_transfer spdk_nvme_data_transfer_t;

static spdk_nvme_data_transfer_t
spdk_nvmf_rdma_request_get_xfer(struct spdk_nvmf_rdma_request *rdma_req)
{
	enum spdk_nvme_data_transfer xfer;
	struct spdk_nvme_cmd *cmd = &rdma_req->req.cmd->nvme_cmd;
	struct spdk_nvme_sgl_descriptor *sgl = &cmd->dptr.sgl1;

	/* Figure out data transfer direction */
	if (cmd->opc == SPDK_NVME_OPC_FABRIC) {
		xfer = spdk_nvme_opc_get_data_transfer(rdma_req->req.cmd->nvmf_cmd.fctype);
	} else {
		xfer = spdk_nvme_opc_get_data_transfer(cmd->opc);

		/* Some admin commands are special cases */
		if ((rdma_req->req.qpair->qid == 0) &&
		    ((cmd->opc == SPDK_NVME_OPC_GET_FEATURES) ||
		     (cmd->opc == SPDK_NVME_OPC_SET_FEATURES))) {
			switch (cmd->cdw10 & 0xff) {
			case SPDK_NVME_FEAT_LBA_RANGE_TYPE:
			case SPDK_NVME_FEAT_AUTONOMOUS_POWER_STATE_TRANSITION:
			case SPDK_NVME_FEAT_HOST_IDENTIFIER:
				break;
			default:
				xfer = SPDK_NVME_DATA_NONE;
			}
		}
	}

	if (xfer == SPDK_NVME_DATA_NONE) {
		return xfer;
	}

	/* Even for commands that may transfer data, they could have specified 0 length.
	 * We want those to show up with xfer SPDK_NVME_DATA_NONE.
	 */
	switch (sgl->generic.type) {
	case SPDK_NVME_SGL_TYPE_DATA_BLOCK:
	case SPDK_NVME_SGL_TYPE_BIT_BUCKET:
	case SPDK_NVME_SGL_TYPE_SEGMENT:
	case SPDK_NVME_SGL_TYPE_LAST_SEGMENT:
		if (sgl->unkeyed.length == 0) {
			xfer = SPDK_NVME_DATA_NONE;
		}
		break;
	case SPDK_NVME_SGL_TYPE_KEYED_DATA_BLOCK:
		if (sgl->keyed.length == 0) {
			xfer = SPDK_NVME_DATA_NONE;
		}
		break;
	}

	return xfer;
}

static int
spdk_nvmf_rdma_request_parse_sgl(struct spdk_nvmf_rdma_transport *rtransport,
				 struct spdk_nvmf_rdma_device *device,
				 struct spdk_nvmf_rdma_request *rdma_req)
{
	struct spdk_nvme_cmd			*cmd;
	struct spdk_nvme_cpl			*rsp;
	struct spdk_nvme_sgl_descriptor		*sgl;

	cmd = &rdma_req->req.cmd->nvme_cmd;
	rsp = &rdma_req->req.rsp->nvme_cpl;
	sgl = &cmd->dptr.sgl1;

	if (sgl->generic.type == SPDK_NVME_SGL_TYPE_KEYED_DATA_BLOCK &&
	    (sgl->keyed.subtype == SPDK_NVME_SGL_SUBTYPE_ADDRESS ||
	     sgl->keyed.subtype == SPDK_NVME_SGL_SUBTYPE_INVALIDATE_KEY)) {
		if (sgl->keyed.length > rtransport->max_io_size) {
			SPDK_ERRLOG("SGL length 0x%x exceeds max io size 0x%x\n",
				    sgl->keyed.length, rtransport->max_io_size);
			rsp->status.sc = SPDK_NVME_SC_DATA_SGL_LENGTH_INVALID;
			return -1;
		}

		rdma_req->req.length = sgl->keyed.length;
		rdma_req->req.data = spdk_mempool_get(rtransport->data_buf_pool);
		if (!rdma_req->req.data) {
			/* No available buffers. Queue this request up. */
			SPDK_TRACELOG(SPDK_TRACE_RDMA, "No available large data buffers. Queueing request %p\n", rdma_req);
			return 0;
		}

		rdma_req->data_from_pool = true;
		rdma_req->data.sgl[0].addr = (uintptr_t)rdma_req->req.data;
		rdma_req->data.sgl[0].length = sgl->keyed.length;
		rdma_req->data.sgl[0].lkey = ((struct ibv_mr *)spdk_mem_map_translate(device->map,
					      (uint64_t)rdma_req->req.data))->lkey;
		rdma_req->data.wr.wr.rdma.rkey = sgl->keyed.key;
		rdma_req->data.wr.wr.rdma.remote_addr = sgl->address;

		SPDK_TRACELOG(SPDK_TRACE_RDMA, "Request %p took buffer from central pool\n", rdma_req);

		return 0;
	} else if (sgl->generic.type == SPDK_NVME_SGL_TYPE_DATA_BLOCK &&
		   sgl->unkeyed.subtype == SPDK_NVME_SGL_SUBTYPE_OFFSET) {
		uint64_t offset = sgl->address;
		uint32_t max_len = rtransport->in_capsule_data_size;

		SPDK_TRACELOG(SPDK_TRACE_NVMF, "In-capsule data: offset 0x%" PRIx64 ", length 0x%x\n",
			      offset, sgl->unkeyed.length);

		if (offset > max_len) {
			SPDK_ERRLOG("In-capsule offset 0x%" PRIx64 " exceeds capsule length 0x%x\n",
				    offset, max_len);
			rsp->status.sc = SPDK_NVME_SC_INVALID_SGL_OFFSET;
			return -1;
		}
		max_len -= (uint32_t)offset;

		if (sgl->unkeyed.length > max_len) {
			SPDK_ERRLOG("In-capsule data length 0x%x exceeds capsule length 0x%x\n",
				    sgl->unkeyed.length, max_len);
			rsp->status.sc = SPDK_NVME_SC_DATA_SGL_LENGTH_INVALID;
			return -1;
		}

		rdma_req->req.data = rdma_req->recv->buf + offset;
		rdma_req->data_from_pool = false;
		rdma_req->req.length = sgl->unkeyed.length;
		return 0;
	}

	SPDK_ERRLOG("Invalid NVMf I/O Command SGL:  Type 0x%x, Subtype 0x%x\n",
		    sgl->generic.type, sgl->generic.subtype);
	rsp->status.sc = SPDK_NVME_SC_SGL_DESCRIPTOR_TYPE_INVALID;
	return -1;
}

static spdk_nvmf_request_prep_type
spdk_nvmf_request_prep_data(struct spdk_nvmf_request *req)
{

	struct spdk_nvmf_rdma_request		*rdma_req;
	struct spdk_nvmf_rdma_transport		*rtransport;
	struct spdk_nvmf_rdma_device		*device;
	int					rc;

	rdma_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_rdma_request, req);

	req->length = 0;
	req->data = NULL;

	req->xfer = spdk_nvmf_rdma_request_get_xfer(rdma_req);
	if (req->xfer == SPDK_NVME_DATA_NONE) {
		return SPDK_NVMF_REQUEST_PREP_READY;
	}

	rtransport = SPDK_CONTAINEROF(req->qpair->transport, struct spdk_nvmf_rdma_transport, transport);
	device = SPDK_CONTAINEROF(req->qpair, struct spdk_nvmf_rdma_qpair, qpair)->port->device;

	rc = spdk_nvmf_rdma_request_parse_sgl(rtransport, device, rdma_req);
	if (rc < 0) {
		return SPDK_NVMF_REQUEST_PREP_ERROR;
	}

	if (!req->data) {
		return SPDK_NVMF_REQUEST_PREP_PENDING_BUFFER;
	}

	/* If data is transferring from host to controller and the data didn't
	 * arrive using in capsule data, we need to do a transfer from the host.
	 */
	if (req->xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER && rdma_req->data_from_pool) {
		return SPDK_NVMF_REQUEST_PREP_PENDING_DATA;
	}

	return SPDK_NVMF_REQUEST_PREP_READY;
}

static int
spdk_nvmf_rdma_handle_pending_rdma_rw(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_rdma_qpair		*rdma_qpair;
	struct spdk_nvmf_rdma_transport		*rtransport;
	struct spdk_nvmf_rdma_request		*rdma_req, *tmp;
	int 					rc;
	int 					count = 0;

	rdma_qpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair);
	rtransport = SPDK_CONTAINEROF(qpair->transport, struct spdk_nvmf_rdma_transport, transport);

	/* First, try to assign free data buffers to requests that need one */
	if (qpair->ctrlr) {
		TAILQ_FOREACH_SAFE(rdma_req, &rdma_qpair->pending_data_buf_queue, link, tmp) {
			assert(rdma_req->req.data == NULL);
			rdma_req->req.data = spdk_mempool_get(rtransport->data_buf_pool);
			if (!rdma_req->req.data) {
				break;
			}
			rdma_req->data.sgl[0].addr = (uintptr_t)rdma_req->req.data;
			rdma_req->data.sgl[0].lkey = ((struct ibv_mr *)spdk_mem_map_translate(rdma_qpair->port->device->map,
						      (uint64_t)rdma_req->req.data))->lkey;
			rdma_req->data_from_pool = true;
			TAILQ_REMOVE(&rdma_qpair->pending_data_buf_queue, rdma_req, link);
			if (rdma_req->req.xfer == SPDK_NVME_DATA_HOST_TO_CONTROLLER) {
				TAILQ_INSERT_TAIL(&rdma_qpair->pending_rdma_rw_queue, rdma_req, link);
			} else {
				rc = spdk_nvmf_request_exec(&rdma_req->req);
				if (rc < 0) {
					return -1;
				}
				count++;
			}
		}
	}

	/* Try to initiate RDMA Reads or Writes on requests that have data buffers */
	while (rdma_qpair->cur_rdma_rw_depth < rdma_qpair->max_rw_depth) {
		rdma_req = TAILQ_FIRST(&rdma_qpair->pending_rdma_rw_queue);
		if (spdk_unlikely(!rdma_req)) {
			break;
		}

		TAILQ_REMOVE(&rdma_qpair->pending_rdma_rw_queue, rdma_req, link);

		SPDK_TRACELOG(SPDK_TRACE_RDMA, "Submitting previously queued for RDMA R/W request %p\n", rdma_req);

		rc = spdk_nvmf_rdma_request_transfer_data(&rdma_req->req);
		if (rc) {
			return -1;
		}
	}

	return count;
}

/* Public API callbacks begin here */

static struct spdk_nvmf_transport *
spdk_nvmf_rdma_create(struct spdk_nvmf_tgt *tgt)
{
	int rc;
	struct spdk_nvmf_rdma_transport *rtransport;
	struct spdk_nvmf_rdma_device	*device, *tmp;
	struct ibv_context		**contexts;
	uint32_t			i;
	char				buf[64];

	rtransport = calloc(1, sizeof(*rtransport));
	if (!rtransport) {
		return NULL;
	}

	pthread_mutex_init(&rtransport->lock, NULL);
	TAILQ_INIT(&rtransport->devices);
	TAILQ_INIT(&rtransport->ports);

	rtransport->transport.tgt = tgt;
	rtransport->transport.ops = &spdk_nvmf_transport_rdma;

	SPDK_NOTICELOG("*** RDMA Transport Init ***\n");

	rtransport->max_queue_depth = tgt->max_queue_depth;
	rtransport->max_io_size = tgt->max_io_size;
	rtransport->in_capsule_data_size = tgt->in_capsule_data_size;

	rtransport->event_channel = rdma_create_event_channel();
	if (rtransport->event_channel == NULL) {
		spdk_strerror_r(errno, buf, sizeof(buf));
		SPDK_ERRLOG("rdma_create_event_channel() failed, %s\n", buf);
		free(rtransport);
		return NULL;
	}

	rc = fcntl(rtransport->event_channel->fd, F_SETFL, O_NONBLOCK);
	if (rc < 0) {
		SPDK_ERRLOG("fcntl to set fd to non-blocking failed\n");
		free(rtransport);
		return NULL;
	}

	rtransport->data_buf_pool = spdk_mempool_create("spdk_nvmf_rdma",
				    rtransport->max_queue_depth * 4, /* The 4 is arbitrarily chosen. Needs to be configurable. */
				    rtransport->max_io_size,
				    SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
				    SPDK_ENV_SOCKET_ID_ANY);
	if (!rtransport->data_buf_pool) {
		SPDK_ERRLOG("Unable to allocate buffer pool for poll group\n");
		free(rtransport);
		return NULL;
	}

	contexts = rdma_get_devices(NULL);
	i = 0;
	rc = 0;
	while (contexts[i] != NULL) {
		device = calloc(1, sizeof(*device));
		if (!device) {
			SPDK_ERRLOG("Unable to allocate memory for RDMA devices.\n");
			rc = -ENOMEM;
			break;
		}
		device->context = contexts[i];
		rc = ibv_query_device(device->context, &device->attr);
		if (rc < 0) {
			SPDK_ERRLOG("Failed to query RDMA device attributes.\n");
			free(device);
			break;

		}

		device->pd = NULL;
		device->map = NULL;

		TAILQ_INSERT_TAIL(&rtransport->devices, device, link);
		i++;
	}

	if (rc < 0) {
		TAILQ_FOREACH_SAFE(device, &rtransport->devices, link, tmp) {
			TAILQ_REMOVE(&rtransport->devices, device, link);
			free(device);
		}
		spdk_mempool_free(rtransport->data_buf_pool);
		rdma_destroy_event_channel(rtransport->event_channel);
		free(rtransport);
		rdma_free_devices(contexts);
		return NULL;
	}

	rdma_free_devices(contexts);

	return &rtransport->transport;
}

static int
spdk_nvmf_rdma_destroy(struct spdk_nvmf_transport *transport)
{
	struct spdk_nvmf_rdma_transport	*rtransport;
	struct spdk_nvmf_rdma_device	*device, *device_tmp;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_rdma_transport, transport);

	assert(TAILQ_EMPTY(&rtransport->ports));
	if (rtransport->event_channel != NULL) {
		rdma_destroy_event_channel(rtransport->event_channel);
	}

	TAILQ_FOREACH_SAFE(device, &rtransport->devices, link, device_tmp) {
		TAILQ_REMOVE(&rtransport->devices, device, link);
		if (device->map) {
			spdk_mem_map_free(&device->map);
		}
		free(device);
	}

	spdk_mempool_free(rtransport->data_buf_pool);
	free(rtransport);

	return 0;
}

static int
spdk_nvmf_rdma_listen(struct spdk_nvmf_transport *transport,
		      const struct spdk_nvme_transport_id *trid)
{
	struct spdk_nvmf_rdma_transport *rtransport;
	struct spdk_nvmf_rdma_device	*device;
	struct spdk_nvmf_rdma_port 	*port_tmp, *port;
	struct sockaddr_in saddr;
	int rc;

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_rdma_transport, transport);

	port = calloc(1, sizeof(*port));
	if (!port) {
		return -ENOMEM;
	}

	/* Selectively copy the trid. Things like NQN don't matter here - that
	 * mapping is enforced elsewhere.
	 */
	port->trid.trtype = SPDK_NVME_TRANSPORT_RDMA;
	port->trid.adrfam = trid->adrfam;
	snprintf(port->trid.traddr, sizeof(port->trid.traddr), "%s", trid->traddr);
	snprintf(port->trid.trsvcid, sizeof(port->trid.trsvcid), "%s", trid->trsvcid);

	pthread_mutex_lock(&rtransport->lock);
	assert(rtransport->event_channel != NULL);
	TAILQ_FOREACH(port_tmp, &rtransport->ports, link) {
		if (spdk_nvme_transport_id_compare(&port_tmp->trid, &port->trid) == 0) {
			port_tmp->ref++;
			free(port);
			/* Already listening at this address */
			pthread_mutex_unlock(&rtransport->lock);
			return 0;
		}
	}

	rc = rdma_create_id(rtransport->event_channel, &port->id, port, RDMA_PS_TCP);
	if (rc < 0) {
		SPDK_ERRLOG("rdma_create_id() failed\n");
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return rc;
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = inet_addr(port->trid.traddr);
	saddr.sin_port = htons((uint16_t)strtoul(port->trid.trsvcid, NULL, 10));
	rc = rdma_bind_addr(port->id, (struct sockaddr *)&saddr);
	if (rc < 0) {
		SPDK_ERRLOG("rdma_bind_addr() failed\n");
		rdma_destroy_id(port->id);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return rc;
	}

	rc = rdma_listen(port->id, 10); /* 10 = backlog */
	if (rc < 0) {
		SPDK_ERRLOG("rdma_listen() failed\n");
		rdma_destroy_id(port->id);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return rc;
	}

	TAILQ_FOREACH(device, &rtransport->devices, link) {
		if (device->context == port->id->verbs) {
			port->device = device;
			break;
		}
	}
	if (!port->device) {
		SPDK_ERRLOG("Accepted a connection with verbs %p, but unable to find a corresponding device.\n",
			    port->id->verbs);
		rdma_destroy_id(port->id);
		free(port);
		pthread_mutex_unlock(&rtransport->lock);
		return -EINVAL;
	}

	if (!device->map) {
		device->pd = port->id->pd;
		device->map = spdk_mem_map_alloc(0, spdk_nvmf_rdma_mem_notify, device);
		if (!device->map) {
			SPDK_ERRLOG("Unable to allocate memory map for new poll group\n");
			return -1;
		}
	} else {
		assert(device->pd == port->id->pd);
	}

	SPDK_NOTICELOG("*** NVMf Target Listening on %s port %d ***\n",
		       port->trid.traddr, ntohs(rdma_get_src_port(port->id)));

	port->ref = 1;

	TAILQ_INSERT_TAIL(&rtransport->ports, port, link);
	pthread_mutex_unlock(&rtransport->lock);

	return 0;
}

static int
spdk_nvmf_rdma_stop_listen(struct spdk_nvmf_transport *transport,
			   const struct spdk_nvme_transport_id *_trid)
{
	struct spdk_nvmf_rdma_transport *rtransport;
	struct spdk_nvmf_rdma_port *port, *tmp;
	struct spdk_nvme_transport_id trid = {};

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_rdma_transport, transport);

	/* Selectively copy the trid. Things like NQN don't matter here - that
	 * mapping is enforced elsewhere.
	 */
	trid.trtype = SPDK_NVME_TRANSPORT_RDMA;
	trid.adrfam = _trid->adrfam;
	snprintf(trid.traddr, sizeof(port->trid.traddr), "%s", _trid->traddr);
	snprintf(trid.trsvcid, sizeof(port->trid.trsvcid), "%s", _trid->trsvcid);

	pthread_mutex_lock(&rtransport->lock);
	TAILQ_FOREACH_SAFE(port, &rtransport->ports, link, tmp) {
		if (spdk_nvme_transport_id_compare(&port->trid, &trid) == 0) {
			assert(port->ref > 0);
			port->ref--;
			if (port->ref == 0) {
				TAILQ_REMOVE(&rtransport->ports, port, link);
				rdma_destroy_id(port->id);
				free(port);
			}
			break;
		}
	}

	pthread_mutex_unlock(&rtransport->lock);
	return 0;
}

static int
spdk_nvmf_rdma_poll(struct spdk_nvmf_qpair *qpair);

static void
spdk_nvmf_rdma_accept(struct spdk_nvmf_transport *transport)
{
	struct spdk_nvmf_rdma_transport *rtransport;
	struct rdma_cm_event		*event;
	int				rc;
	struct spdk_nvmf_rdma_qpair	*rdma_qpair, *tmp;
	char buf[64];

	rtransport = SPDK_CONTAINEROF(transport, struct spdk_nvmf_rdma_transport, transport);

	if (rtransport->event_channel == NULL) {
		return;
	}

	/* Process pending connections for incoming capsules. The only capsule
	 * this should ever find is a CONNECT request. */
	TAILQ_FOREACH_SAFE(rdma_qpair, &g_pending_conns, link, tmp) {
		rc = spdk_nvmf_rdma_poll(&rdma_qpair->qpair);
		if (rc < 0) {
			TAILQ_REMOVE(&g_pending_conns, rdma_qpair, link);
			spdk_nvmf_rdma_qpair_destroy(rdma_qpair);
		} else if (rc > 0) {
			/* At least one request was processed which is assumed to be
			 * a CONNECT. Remove this connection from our list. */
			TAILQ_REMOVE(&g_pending_conns, rdma_qpair, link);
		}
	}

	while (1) {
		rc = rdma_get_cm_event(rtransport->event_channel, &event);
		if (rc == 0) {
			SPDK_TRACELOG(SPDK_TRACE_RDMA, "Acceptor Event: %s\n", CM_EVENT_STR[event->event]);

			switch (event->event) {
			case RDMA_CM_EVENT_CONNECT_REQUEST:
				rc = nvmf_rdma_connect(transport, event);
				if (rc < 0) {
					SPDK_ERRLOG("Unable to process connect event. rc: %d\n", rc);
					break;
				}
				break;
			case RDMA_CM_EVENT_ESTABLISHED:
				break;
			case RDMA_CM_EVENT_ADDR_CHANGE:
			case RDMA_CM_EVENT_DISCONNECTED:
			case RDMA_CM_EVENT_DEVICE_REMOVAL:
			case RDMA_CM_EVENT_TIMEWAIT_EXIT:
				rc = nvmf_rdma_disconnect(event);
				if (rc < 0) {
					SPDK_ERRLOG("Unable to process disconnect event. rc: %d\n", rc);
					break;
				}
				continue;
			default:
				SPDK_ERRLOG("Unexpected Acceptor Event [%d]\n", event->event);
				break;
			}

			rdma_ack_cm_event(event);
		} else {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				spdk_strerror_r(errno, buf, sizeof(buf));
				SPDK_ERRLOG("Acceptor Event Error: %s\n", buf);
			}
			break;
		}
	}
}

static void
spdk_nvmf_rdma_discover(struct spdk_nvmf_transport *transport,
			struct spdk_nvmf_listen_addr *port,
			struct spdk_nvmf_discovery_log_page_entry *entry)
{
	entry->trtype = SPDK_NVMF_TRTYPE_RDMA;
	entry->adrfam = port->trid.adrfam;
	entry->treq.secure_channel = SPDK_NVMF_TREQ_SECURE_CHANNEL_NOT_SPECIFIED;

	spdk_strcpy_pad(entry->trsvcid, port->trid.trsvcid, sizeof(entry->trsvcid), ' ');
	spdk_strcpy_pad(entry->traddr, port->trid.traddr, sizeof(entry->traddr), ' ');

	entry->tsas.rdma.rdma_qptype = SPDK_NVMF_RDMA_QPTYPE_RELIABLE_CONNECTED;
	entry->tsas.rdma.rdma_prtype = SPDK_NVMF_RDMA_PRTYPE_NONE;
	entry->tsas.rdma.rdma_cms = SPDK_NVMF_RDMA_CMS_RDMA_CM;
}

static struct spdk_nvmf_poll_group *
spdk_nvmf_rdma_poll_group_create(struct spdk_nvmf_transport *transport)
{
	struct spdk_nvmf_rdma_poll_group	*rgroup;

	rgroup = calloc(1, sizeof(*rgroup));
	if (!rgroup) {
		return NULL;
	}

	return &rgroup->group;
}

static void
spdk_nvmf_rdma_poll_group_destroy(struct spdk_nvmf_poll_group *group)
{
	struct spdk_nvmf_rdma_poll_group	*rgroup;

	rgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_rdma_poll_group, group);

	if (!rgroup) {
		return;
	}

	free(rgroup);
}

static int
spdk_nvmf_rdma_poll_group_add(struct spdk_nvmf_poll_group *group,
			      struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_rdma_poll_group	*rgroup;
	struct spdk_nvmf_rdma_qpair 		*rdma_qpair;
	struct spdk_nvmf_rdma_transport		*rtransport;
	struct spdk_nvmf_rdma_device 		*device;

	rgroup = SPDK_CONTAINEROF(group, struct spdk_nvmf_rdma_poll_group, group);
	rdma_qpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair);
	rtransport = SPDK_CONTAINEROF(group->transport, struct spdk_nvmf_rdma_transport, transport);

	if (rgroup->device != NULL) {
		if (rgroup->device->context != rdma_qpair->cm_id->verbs) {
			SPDK_ERRLOG("Attempted to add a qpair to a poll group with mismatched RDMA devices.\n");
			return -1;
		}

		if (rgroup->device->pd != rdma_qpair->cm_id->pd) {
			SPDK_ERRLOG("Mismatched protection domains\n");
			return -1;
		}

		return 0;
	}

	TAILQ_FOREACH(device, &rtransport->devices, link) {
		if (device->context == rdma_qpair->cm_id->verbs) {
			break;
		}
	}
	if (!device) {
		SPDK_ERRLOG("Attempted to add a qpair with an unknown device\n");
		return -EINVAL;
	}

	rgroup->device = device;

	return 0;
}

static int
spdk_nvmf_rdma_poll_group_remove(struct spdk_nvmf_poll_group *group,
				 struct spdk_nvmf_qpair *qpair)
{
	return 0;
}

static int
spdk_nvmf_rdma_request_complete(struct spdk_nvmf_request *req)
{
	struct spdk_nvme_cpl *rsp = &req->rsp->nvme_cpl;
	int rc;

	if (rsp->status.sc == SPDK_NVME_SC_SUCCESS &&
	    req->xfer == SPDK_NVME_DATA_CONTROLLER_TO_HOST) {
		rc = spdk_nvmf_rdma_request_transfer_data(req);
	} else {
		rc = request_transfer_out(req);
	}

	return rc;
}

static void
request_release_buffer(struct spdk_nvmf_request *req)
{
	struct spdk_nvmf_rdma_request	*rdma_req;
	struct spdk_nvmf_qpair		*qpair = req->qpair;
	struct spdk_nvmf_rdma_transport	*rtransport;

	rdma_req = SPDK_CONTAINEROF(req, struct spdk_nvmf_rdma_request, req);
	rtransport = SPDK_CONTAINEROF(qpair->transport, struct spdk_nvmf_rdma_transport, transport);

	if (rdma_req->data_from_pool) {
		/* Put the buffer back in the pool */
		spdk_mempool_put(rtransport->data_buf_pool, req->data);
		req->data = NULL;
		req->length = 0;
		rdma_req->data_from_pool = false;
	}
}

static void
spdk_nvmf_rdma_close_qpair(struct spdk_nvmf_qpair *qpair)
{
	spdk_nvmf_rdma_qpair_destroy(SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair));
}

static int
process_incoming_queue(struct spdk_nvmf_rdma_qpair *rdma_qpair)
{
	struct spdk_nvmf_rdma_recv	*rdma_recv, *tmp;
	struct spdk_nvmf_rdma_request	*rdma_req;
	struct spdk_nvmf_request	*req;
	int rc, count;
	bool error = false;

	count = 0;
	TAILQ_FOREACH_SAFE(rdma_recv, &rdma_qpair->incoming_queue, link, tmp) {
		rdma_req = TAILQ_FIRST(&rdma_qpair->free_queue);
		if (rdma_req == NULL) {
			/* Need to wait for more SEND completions */
			break;
		}
		TAILQ_REMOVE(&rdma_qpair->free_queue, rdma_req, link);
		TAILQ_REMOVE(&rdma_qpair->incoming_queue, rdma_recv, link);
		rdma_req->recv = rdma_recv;
		req = &rdma_req->req;

		/* The first element of the SGL is the NVMe command */
		req->cmd = (union nvmf_h2c_msg *)rdma_recv->sgl[0].addr;

		spdk_trace_record(TRACE_NVMF_IO_START, 0, 0, (uint64_t)req, 0);

		memset(req->rsp, 0, sizeof(*req->rsp));
		rc = spdk_nvmf_request_prep_data(req);
		switch (rc) {
		case SPDK_NVMF_REQUEST_PREP_READY:
			SPDK_TRACELOG(SPDK_TRACE_RDMA, "Request %p is ready for execution\n", req);
			/* Data is immediately available */
			rc = spdk_nvmf_request_exec(req);
			if (rc < 0) {
				error = true;
				continue;
			}
			count++;
			break;
		case SPDK_NVMF_REQUEST_PREP_PENDING_BUFFER:
			SPDK_TRACELOG(SPDK_TRACE_RDMA, "Request %p needs data buffer\n", req);
			TAILQ_INSERT_TAIL(&rdma_qpair->pending_data_buf_queue, rdma_req, link);
			break;
		case SPDK_NVMF_REQUEST_PREP_PENDING_DATA:
			SPDK_TRACELOG(SPDK_TRACE_RDMA, "Request %p needs data transfer\n", req);
			rc = spdk_nvmf_rdma_request_transfer_data(req);
			if (rc < 0) {
				error = true;
				continue;
			}
			break;
		case SPDK_NVMF_REQUEST_PREP_ERROR:
			spdk_nvmf_request_complete(req);
			break;
		}
	}

	if (error) {
		return -1;
	}

	return count;
}

static struct spdk_nvmf_rdma_request *
get_rdma_req_from_wc(struct spdk_nvmf_rdma_qpair *rdma_qpair,
		     struct ibv_wc *wc)
{
	struct spdk_nvmf_rdma_request *rdma_req;

	rdma_req = (struct spdk_nvmf_rdma_request *)wc->wr_id;
	assert(rdma_req != NULL);
	assert(rdma_req - rdma_qpair->reqs >= 0);
	assert(rdma_req - rdma_qpair->reqs < (ptrdiff_t)rdma_qpair->max_queue_depth);

	return rdma_req;
}

static struct spdk_nvmf_rdma_recv *
get_rdma_recv_from_wc(struct spdk_nvmf_rdma_qpair *rdma_qpair,
		      struct ibv_wc *wc)
{
	struct spdk_nvmf_rdma_recv *rdma_recv;

	assert(wc->byte_len >= sizeof(struct spdk_nvmf_capsule_cmd));

	rdma_recv = (struct spdk_nvmf_rdma_recv *)wc->wr_id;
	assert(rdma_recv != NULL);
	assert(rdma_recv - rdma_qpair->recvs >= 0);
	assert(rdma_recv - rdma_qpair->recvs < (ptrdiff_t)rdma_qpair->max_queue_depth);

	return rdma_recv;
}

/* Returns the number of times that spdk_nvmf_request_exec was called,
 * or -1 on error.
 */
static int
spdk_nvmf_rdma_poll(struct spdk_nvmf_qpair *qpair)
{
	struct ibv_wc wc[32];
	struct spdk_nvmf_rdma_qpair *rdma_qpair;
	struct spdk_nvmf_rdma_request *rdma_req;
	struct spdk_nvmf_rdma_recv    *rdma_recv;
	struct spdk_nvmf_request *req;
	int reaped, i, rc;
	int count = 0;
	bool error = false;
	char buf[64];

	rdma_qpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair);

	/* Poll for completing operations. */
	rc = ibv_poll_cq(rdma_qpair->cq, 32, wc);
	if (rc < 0) {
		spdk_strerror_r(errno, buf, sizeof(buf));
		SPDK_ERRLOG("Error polling CQ! (%d): %s\n",
			    errno, buf);
		return -1;
	}

	reaped = rc;
	for (i = 0; i < reaped; i++) {
		if (wc[i].status) {
			SPDK_ERRLOG("CQ error on Connection %p, Request 0x%lu (%d): %s\n",
				    qpair, wc[i].wr_id, wc[i].status, ibv_wc_status_str(wc[i].status));
			error = true;
			continue;
		}

		switch (wc[i].opcode) {
		case IBV_WC_SEND:
			rdma_req = get_rdma_req_from_wc(rdma_qpair, &wc[i]);
			req = &rdma_req->req;

			assert(rdma_qpair->cur_queue_depth > 0);
			SPDK_TRACELOG(SPDK_TRACE_RDMA,
				      "RDMA SEND Complete. Request: %p Connection: %p Outstanding I/O: %d\n",
				      req, qpair, rdma_qpair->cur_queue_depth - 1);
			rdma_qpair->cur_queue_depth--;

			/* The request may still own a data buffer. Release it */
			request_release_buffer(req);

			/* Put the request back on the free list */
			TAILQ_INSERT_TAIL(&rdma_qpair->free_queue, rdma_req, link);

			/* Try to process queued incoming requests */
			rc = process_incoming_queue(rdma_qpair);
			if (rc < 0) {
				error = true;
				continue;
			}
			count += rc;
			break;

		case IBV_WC_RDMA_WRITE:
			rdma_req = get_rdma_req_from_wc(rdma_qpair, &wc[i]);
			req = &rdma_req->req;

			SPDK_TRACELOG(SPDK_TRACE_RDMA, "RDMA WRITE Complete. Request: %p Connection: %p\n",
				      req, qpair);
			spdk_trace_record(TRACE_RDMA_WRITE_COMPLETE, 0, 0, (uint64_t)req, 0);

			/* Now that the write has completed, the data buffer can be released */
			request_release_buffer(req);

			rdma_qpair->cur_rdma_rw_depth--;

			/* Since an RDMA R/W operation completed, try to submit from the pending list. */
			rc = spdk_nvmf_rdma_handle_pending_rdma_rw(qpair);
			if (rc < 0) {
				error = true;
				continue;
			}
			count += rc;
			break;

		case IBV_WC_RDMA_READ:
			rdma_req = get_rdma_req_from_wc(rdma_qpair, &wc[i]);
			req = &rdma_req->req;

			SPDK_TRACELOG(SPDK_TRACE_RDMA, "RDMA READ Complete. Request: %p Connection: %p\n",
				      req, qpair);
			spdk_trace_record(TRACE_RDMA_READ_COMPLETE, 0, 0, (uint64_t)req, 0);
			rc = spdk_nvmf_request_exec(req);
			if (rc) {
				error = true;
				continue;
			}
			count++;

			/* Since an RDMA R/W operation completed, try to submit from the pending list. */
			rdma_qpair->cur_rdma_rw_depth--;
			rc = spdk_nvmf_rdma_handle_pending_rdma_rw(qpair);
			if (rc < 0) {
				error = true;
				continue;
			}
			count += rc;
			break;

		case IBV_WC_RECV:
			rdma_recv = get_rdma_recv_from_wc(rdma_qpair, &wc[i]);

			rdma_qpair->cur_queue_depth++;
			if (rdma_qpair->cur_queue_depth > rdma_qpair->max_queue_depth) {
				SPDK_TRACELOG(SPDK_TRACE_RDMA,
					      "Temporarily exceeded maximum queue depth (%u). Queueing.\n",
					      rdma_qpair->cur_queue_depth);
			}
			SPDK_TRACELOG(SPDK_TRACE_RDMA,
				      "RDMA RECV Complete. Recv: %p Connection: %p Outstanding I/O: %d\n",
				      rdma_recv, qpair, rdma_qpair->cur_queue_depth);

			TAILQ_INSERT_TAIL(&rdma_qpair->incoming_queue, rdma_recv, link);
			rc = process_incoming_queue(rdma_qpair);
			if (rc < 0) {
				error = true;
				continue;
			}
			count += rc;
			break;

		default:
			SPDK_ERRLOG("Received an unknown opcode on the CQ: %d\n", wc[i].opcode);
			error = true;
			continue;
		}
	}

	if (error == true) {
		return -1;
	}

	return count;
}

static bool
spdk_nvmf_rdma_qpair_is_idle(struct spdk_nvmf_qpair *qpair)
{
	struct spdk_nvmf_rdma_qpair *rdma_qpair;

	rdma_qpair = SPDK_CONTAINEROF(qpair, struct spdk_nvmf_rdma_qpair, qpair);

	if (rdma_qpair->cur_queue_depth == 0 && rdma_qpair->cur_rdma_rw_depth == 0) {
		return true;
	}
	return false;
}

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_rdma = {
	.type = SPDK_NVME_TRANSPORT_RDMA,
	.create = spdk_nvmf_rdma_create,
	.destroy = spdk_nvmf_rdma_destroy,

	.listen = spdk_nvmf_rdma_listen,
	.stop_listen = spdk_nvmf_rdma_stop_listen,
	.accept = spdk_nvmf_rdma_accept,

	.listen_addr_discover = spdk_nvmf_rdma_discover,

	.poll_group_create = spdk_nvmf_rdma_poll_group_create,
	.poll_group_destroy = spdk_nvmf_rdma_poll_group_destroy,
	.poll_group_add = spdk_nvmf_rdma_poll_group_add,
	.poll_group_remove = spdk_nvmf_rdma_poll_group_remove,

	.req_complete = spdk_nvmf_rdma_request_complete,

	.qpair_fini = spdk_nvmf_rdma_close_qpair,
	.qpair_poll = spdk_nvmf_rdma_poll,
	.qpair_is_idle = spdk_nvmf_rdma_qpair_is_idle,

};

SPDK_LOG_REGISTER_TRACE_FLAG("rdma", SPDK_TRACE_RDMA)
