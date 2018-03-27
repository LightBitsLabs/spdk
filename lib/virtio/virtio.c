/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
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

#include <linux/virtio_scsi.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_config.h>

#include <rte_config.h>
#include <rte_memcpy.h>
#include <rte_string_fns.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_pci.h>
#include <rte_common.h>
#include <rte_errno.h>

#include <rte_eal.h>
#include <rte_dev.h>
#include <rte_prefetch.h>

#include "spdk/env.h"
#include "spdk/barrier.h"

#include "spdk_internal/virtio.h"

/* We use SMP memory barrier variants as all virtio_pci devices
 * are purely virtual. All MMIO is executed on a CPU core, so
 * there's no need to do full MMIO synchronization.
 */
#define virtio_mb()	spdk_smp_mb()
#define virtio_rmb()	spdk_smp_rmb()
#define virtio_wmb()	spdk_smp_wmb()

/* Chain all the descriptors in the ring with an END */
static inline void
vring_desc_init(struct vring_desc *dp, uint16_t n)
{
	uint16_t i;

	for (i = 0; i < n - 1; i++) {
		dp[i].next = (uint16_t)(i + 1);
	}
	dp[i].next = VQ_RING_DESC_CHAIN_END;
}

static void
virtio_init_vring(struct virtqueue *vq)
{
	int size = vq->vq_nentries;
	struct vring *vr = &vq->vq_ring;
	uint8_t *ring_mem = vq->vq_ring_virt_mem;

	/*
	 * Reinitialise since virtio port might have been stopped and restarted
	 */
	memset(ring_mem, 0, vq->vq_ring_size);
	vring_init(vr, size, ring_mem, VIRTIO_PCI_VRING_ALIGN);
	vq->vq_used_cons_idx = 0;
	vq->vq_desc_head_idx = 0;
	vq->vq_avail_idx = 0;
	vq->vq_desc_tail_idx = (uint16_t)(vq->vq_nentries - 1);
	vq->vq_free_cnt = vq->vq_nentries;
	vq->req_start = VQ_RING_DESC_CHAIN_END;
	vq->req_end = VQ_RING_DESC_CHAIN_END;
	memset(vq->vq_descx, 0, sizeof(struct vq_desc_extra) * vq->vq_nentries);

	vring_desc_init(vr->desc, size);

	/* Tell the backend not to interrupt us. */
	vq->vq_ring.avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
}

static int
virtio_init_queue(struct virtio_dev *dev, uint16_t vtpci_queue_idx)
{
	void *queue_mem;
	unsigned int vq_size, size;
	uint64_t queue_mem_phys_addr;
	struct virtqueue *vq;
	int ret;

	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "setting up queue: %"PRIu16"\n", vtpci_queue_idx);

	/*
	 * Read the virtqueue size from the Queue Size field
	 * Always power of 2 and if 0 virtqueue does not exist
	 */
	vq_size = virtio_dev_backend_ops(dev)->get_queue_num(dev, vtpci_queue_idx);
	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "vq_size: %u\n", vq_size);
	if (vq_size == 0) {
		SPDK_ERRLOG("virtqueue %"PRIu16" does not exist\n", vtpci_queue_idx);
		return -EINVAL;
	}

	if (!rte_is_power_of_2(vq_size)) {
		SPDK_ERRLOG("virtqueue %"PRIu16" size (%u) is not powerof 2\n",
			    vtpci_queue_idx, vq_size);
		return -EINVAL;
	}

	size = RTE_ALIGN_CEIL(sizeof(*vq) +
			      vq_size * sizeof(struct vq_desc_extra),
			      RTE_CACHE_LINE_SIZE);

	vq = spdk_dma_zmalloc(size, RTE_CACHE_LINE_SIZE, NULL);
	if (vq == NULL) {
		SPDK_ERRLOG("can not allocate vq\n");
		return -ENOMEM;
	}
	dev->vqs[vtpci_queue_idx] = vq;

	vq->vdev = dev;
	vq->vq_queue_index = vtpci_queue_idx;
	vq->vq_nentries = vq_size;

	/*
	 * Reserve a memzone for vring elements
	 */
	size = vring_size(vq_size, VIRTIO_PCI_VRING_ALIGN);
	vq->vq_ring_size = RTE_ALIGN_CEIL(size, VIRTIO_PCI_VRING_ALIGN);
	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "vring_size: %u, rounded_vring_size: %u\n",
		      size, vq->vq_ring_size);

	queue_mem = spdk_dma_zmalloc(vq->vq_ring_size, VIRTIO_PCI_VRING_ALIGN, &queue_mem_phys_addr);
	if (queue_mem == NULL) {
		ret = -ENOMEM;
		goto fail_q_alloc;
	}

	vq->vq_ring_mem = queue_mem_phys_addr;
	vq->vq_ring_virt_mem = queue_mem;
	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "vq->vq_ring_mem:      0x%" PRIx64 "\n",
		      vq->vq_ring_mem);
	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "vq->vq_ring_virt_mem: 0x%" PRIx64 "\n",
		      (uint64_t)(uintptr_t)vq->vq_ring_virt_mem);

	virtio_init_vring(vq);

	vq->owner_thread = NULL;

	if (virtio_dev_backend_ops(dev)->setup_queue(dev, vq) < 0) {
		SPDK_ERRLOG("setup_queue failed\n");
		return -EINVAL;
	}

	return 0;

fail_q_alloc:
	rte_free(vq);

	return ret;
}

static void
virtio_free_queues(struct virtio_dev *dev)
{
	uint16_t nr_vq = dev->max_queues;
	struct virtqueue *vq;
	uint16_t i;

	if (dev->vqs == NULL) {
		return;
	}

	for (i = 0; i < nr_vq; i++) {
		vq = dev->vqs[i];
		if (!vq) {
			continue;
		}

		spdk_dma_free(vq->vq_ring_virt_mem);

		rte_free(vq);
		dev->vqs[i] = NULL;
	}

	rte_free(dev->vqs);
	dev->vqs = NULL;
}

static int
virtio_alloc_queues(struct virtio_dev *dev, uint16_t request_vq_num, uint16_t fixed_vq_num)
{
	uint16_t nr_vq;
	uint16_t i;
	int ret;

	nr_vq = request_vq_num + fixed_vq_num;
	if (nr_vq == 0) {
		/* perfectly fine to have a device with no virtqueues. */
		return 0;
	}

	assert(dev->vqs == NULL);
	dev->vqs = rte_zmalloc(NULL, sizeof(struct virtqueue *) * nr_vq, 0);
	if (!dev->vqs) {
		SPDK_ERRLOG("failed to allocate %"PRIu16" vqs\n", nr_vq);
		return -ENOMEM;
	}

	for (i = 0; i < nr_vq; i++) {
		ret = virtio_init_queue(dev, i);
		if (ret < 0) {
			virtio_free_queues(dev);
			return ret;
		}
	}

	dev->max_queues = nr_vq;
	dev->fixed_queues_num = fixed_vq_num;
	return 0;
}

/**
 * Negotiate virtio features. For virtio_user this will also set
 * dev->modern flag if VIRTIO_F_VERSION_1 flag is negotiated.
 */
static int
virtio_negotiate_features(struct virtio_dev *dev, uint64_t req_features)
{
	uint64_t host_features = virtio_dev_backend_ops(dev)->get_features(dev);
	int rc;

	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "guest features = %" PRIx64 "\n", req_features);
	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "device features = %" PRIx64 "\n", host_features);

	rc = virtio_dev_backend_ops(dev)->set_features(dev, req_features & host_features);
	if (rc != 0) {
		SPDK_ERRLOG("failed to negotiate device features.\n");
		return -1;
	}

	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "negotiated features = %" PRIx64 "\n",
		      dev->negotiated_features);

	virtio_dev_set_status(dev, VIRTIO_CONFIG_S_FEATURES_OK);
	if (!(virtio_dev_get_status(dev) & VIRTIO_CONFIG_S_FEATURES_OK)) {
		SPDK_ERRLOG("failed to set FEATURES_OK status!\n");
		return -1;
	}

	return 0;
}

int
virtio_dev_construct(struct virtio_dev *vdev, const char *name,
		     const struct virtio_dev_ops *ops, void *ctx)
{
	int rc;

	vdev->name = strdup(name);
	if (vdev->name == NULL) {
		return -ENOMEM;
	}

	rc = pthread_mutex_init(&vdev->mutex, NULL);
	if (rc != 0) {
		free(vdev->name);
		return -rc;
	}

	vdev->backend_ops = ops;
	vdev->ctx = ctx;

	return 0;
}

int
virtio_dev_reset(struct virtio_dev *dev, uint64_t req_features)
{
	req_features |= (1ULL << VIRTIO_F_VERSION_1);

	virtio_dev_stop(dev);

	virtio_dev_set_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);
	if (!(virtio_dev_get_status(dev) & VIRTIO_CONFIG_S_ACKNOWLEDGE)) {
		SPDK_ERRLOG("Failed to set VIRTIO_CONFIG_S_ACKNOWLEDGE status.\n");
		return -1;
	}

	virtio_dev_set_status(dev, VIRTIO_CONFIG_S_DRIVER);
	if (!(virtio_dev_get_status(dev) & VIRTIO_CONFIG_S_DRIVER)) {
		SPDK_ERRLOG("Failed to set VIRTIO_CONFIG_S_DRIVER status.\n");
		return -1;
	}

	return virtio_negotiate_features(dev, req_features);
}

int
virtio_dev_start(struct virtio_dev *vdev, uint16_t max_queues, uint16_t fixed_queue_num)
{
	int ret;

	ret = virtio_alloc_queues(vdev, max_queues, fixed_queue_num);
	if (ret < 0) {
		return ret;
	}

	virtio_dev_set_status(vdev, VIRTIO_CONFIG_S_DRIVER_OK);
	if (!(virtio_dev_get_status(vdev) & VIRTIO_CONFIG_S_DRIVER_OK)) {
		SPDK_ERRLOG("Failed to set VIRTIO_CONFIG_S_DRIVER_OK status.\n");
		return -1;
	}

	return 0;
}

void
virtio_dev_destruct(struct virtio_dev *dev)
{
	virtio_dev_backend_ops(dev)->destruct_dev(dev);
	pthread_mutex_destroy(&dev->mutex);
	free(dev->name);
}

static void
vq_ring_free_chain(struct virtqueue *vq, uint16_t desc_idx)
{
	struct vring_desc *dp, *dp_tail;
	struct vq_desc_extra *dxp;
	uint16_t desc_idx_last = desc_idx;

	dp  = &vq->vq_ring.desc[desc_idx];
	dxp = &vq->vq_descx[desc_idx];
	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt + dxp->ndescs);
	if ((dp->flags & VRING_DESC_F_INDIRECT) == 0) {
		while (dp->flags & VRING_DESC_F_NEXT) {
			desc_idx_last = dp->next;
			dp = &vq->vq_ring.desc[dp->next];
		}
	}
	dxp->ndescs = 0;

	/*
	 * We must append the existing free chain, if any, to the end of
	 * newly freed chain. If the virtqueue was completely used, then
	 * head would be VQ_RING_DESC_CHAIN_END (ASSERTed above).
	 */
	if (vq->vq_desc_tail_idx == VQ_RING_DESC_CHAIN_END) {
		vq->vq_desc_head_idx = desc_idx;
	} else {
		dp_tail = &vq->vq_ring.desc[vq->vq_desc_tail_idx];
		dp_tail->next = desc_idx;
	}

	vq->vq_desc_tail_idx = desc_idx_last;
	dp->next = VQ_RING_DESC_CHAIN_END;
}

static uint16_t
virtqueue_dequeue_burst_rx(struct virtqueue *vq, void **rx_pkts,
			   uint32_t *len, uint16_t num)
{
	struct vring_used_elem *uep;
	struct virtio_req *cookie;
	uint16_t used_idx, desc_idx;
	uint16_t i;

	/*  Caller does the check */
	for (i = 0; i < num ; i++) {
		used_idx = (uint16_t)(vq->vq_used_cons_idx & (vq->vq_nentries - 1));
		uep = &vq->vq_ring.used->ring[used_idx];
		desc_idx = (uint16_t) uep->id;
		len[i] = uep->len;
		cookie = (struct virtio_req *)vq->vq_descx[desc_idx].cookie;

		if (spdk_unlikely(cookie == NULL)) {
			SPDK_WARNLOG("vring descriptor with no mbuf cookie at %"PRIu16"\n",
				     vq->vq_used_cons_idx);
			break;
		}

		rte_prefetch0(cookie);
		rx_pkts[i]  = cookie;
		vq->vq_used_cons_idx++;
		vq_ring_free_chain(vq, desc_idx);
		vq->vq_descx[desc_idx].cookie = NULL;
	}

	return i;
}

int
virtqueue_req_start(struct virtqueue *vq, void *cookie, int iovcnt)
{
	struct vring_desc *desc;
	struct vq_desc_extra *dxp;

	if (iovcnt > vq->vq_free_cnt) {
		return iovcnt > vq->vq_nentries ? -EINVAL : -ENOMEM;
	}

	if (vq->req_start != VQ_RING_DESC_CHAIN_END) {
		desc = &vq->vq_ring.desc[vq->req_end];
		desc->flags &= ~VRING_DESC_F_NEXT;
	}

	vq->req_start = vq->vq_desc_head_idx;
	dxp = &vq->vq_descx[vq->req_start];
	dxp->cookie = cookie;
	dxp->ndescs = 0;

	return 0;
}

void
virtqueue_req_flush(struct virtqueue *vq)
{
	struct vring_desc *desc;
	uint16_t avail_idx;

	if (vq->req_start == VQ_RING_DESC_CHAIN_END) {
		/* no requests have been started */
		return;
	}

	desc = &vq->vq_ring.desc[vq->req_end];
	desc->flags &= ~VRING_DESC_F_NEXT;

	/*
	 * Place the head of the descriptor chain into the next slot and make
	 * it usable to the host. The chain is made available now rather than
	 * deferring to virtqueue_notify() in the hopes that if the host is
	 * currently running on another CPU, we can keep it processing the new
	 * descriptor.
	 */
	avail_idx = (uint16_t)(vq->vq_avail_idx & (vq->vq_nentries - 1));
	if (spdk_unlikely(vq->vq_ring.avail->ring[avail_idx] != vq->req_start)) {
		vq->vq_ring.avail->ring[avail_idx] = vq->req_start;
	}

	vq->vq_avail_idx++;
	vq->req_start = VQ_RING_DESC_CHAIN_END;

	virtio_wmb();
	vq->vq_ring.avail->idx = vq->vq_avail_idx;

	virtio_mb();
	if (spdk_unlikely(!(vq->vq_ring.used->flags & VRING_USED_F_NO_NOTIFY))) {
		virtio_dev_backend_ops(vq->vdev)->notify_queue(vq->vdev, vq);
		SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "Notified backend after xmit\n");
	}
}

void
virtqueue_req_abort(struct virtqueue *vq)
{
	struct vring_desc *desc;

	if (vq->req_start == VQ_RING_DESC_CHAIN_END) {
		/* no requests have been started */
		return;
	}

	desc = &vq->vq_ring.desc[vq->req_end];
	desc->flags &= ~VRING_DESC_F_NEXT;

	vq_ring_free_chain(vq, vq->req_start);
	vq->req_start = VQ_RING_DESC_CHAIN_END;
}

void
virtqueue_req_add_iovs(struct virtqueue *vq, struct iovec *iovs, uint16_t iovcnt,
		       enum spdk_virtio_desc_type desc_type)
{
	struct vring_desc *desc;
	struct vq_desc_extra *dxp;
	uint16_t i, prev_head, new_head;

	assert(vq->req_start != VQ_RING_DESC_CHAIN_END);
	assert(iovcnt <= vq->vq_free_cnt);

	/* TODO use indirect descriptors if iovcnt is high enough
	 * or the caller specifies SPDK_VIRTIO_DESC_F_INDIRECT
	 */

	prev_head = vq->req_end;
	new_head = vq->vq_desc_head_idx;
	for (i = 0; i < iovcnt; ++i) {
		desc = &vq->vq_ring.desc[new_head];

		if (!vq->vdev->is_hw) {
			desc->addr  = (uintptr_t)iovs[i].iov_base;
		} else {
			desc->addr = spdk_vtophys(iovs[i].iov_base);
		}

		desc->len = iovs[i].iov_len;
		/* always set NEXT flag. unset it on the last descriptor
		 * in the request-ending function.
		 */
		desc->flags = desc_type | VRING_DESC_F_NEXT;

		prev_head = new_head;
		new_head = desc->next;
	}

	dxp = &vq->vq_descx[vq->req_start];
	dxp->ndescs += iovcnt;

	vq->req_end = prev_head;
	vq->vq_desc_head_idx = new_head;
	if (vq->vq_desc_head_idx == VQ_RING_DESC_CHAIN_END) {
		assert(vq->vq_free_cnt == 0);
		vq->vq_desc_tail_idx = VQ_RING_DESC_CHAIN_END;
	}
	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - iovcnt);
}

#define DESC_PER_CACHELINE (RTE_CACHE_LINE_SIZE / sizeof(struct vring_desc))
uint16_t
virtio_recv_pkts(struct virtqueue *vq, void **io, uint32_t *len, uint16_t nb_pkts)
{
	uint16_t nb_used, num;

	nb_used = vq->vq_ring.used->idx - vq->vq_used_cons_idx;
	virtio_rmb();

	num = (uint16_t)(spdk_likely(nb_used <= nb_pkts) ? nb_used : nb_pkts);
	if (spdk_likely(num > DESC_PER_CACHELINE)) {
		num = num - ((vq->vq_used_cons_idx + num) % DESC_PER_CACHELINE);
	}

	num = virtqueue_dequeue_burst_rx(vq, io, len, num);
	SPDK_DEBUGLOG(SPDK_LOG_VIRTIO_DEV, "used:%"PRIu16" dequeue:%"PRIu16"\n", nb_used, num);

	return num;
}

int
virtio_dev_acquire_queue(struct virtio_dev *vdev, uint16_t index)
{
	struct virtqueue *vq = NULL;

	if (index >= vdev->max_queues) {
		SPDK_ERRLOG("requested vq index %"PRIu16" exceeds max queue count %"PRIu16".\n",
			    index, vdev->max_queues);
		return -1;
	}

	pthread_mutex_lock(&vdev->mutex);
	vq = vdev->vqs[index];
	if (vq == NULL || vq->owner_thread != NULL) {
		pthread_mutex_unlock(&vdev->mutex);
		return -1;
	}

	vq->owner_thread = spdk_get_thread();
	pthread_mutex_unlock(&vdev->mutex);
	return 0;
}

int32_t
virtio_dev_find_and_acquire_queue(struct virtio_dev *vdev, uint16_t start_index)
{
	struct virtqueue *vq = NULL;
	uint16_t i;

	pthread_mutex_lock(&vdev->mutex);
	for (i = start_index; i < vdev->max_queues; ++i) {
		vq = vdev->vqs[i];
		if (vq != NULL && vq->owner_thread == NULL) {
			break;
		}
	}

	if (vq == NULL || i == vdev->max_queues) {
		SPDK_ERRLOG("no more unused virtio queues with idx >= %"PRIu16".\n", start_index);
		pthread_mutex_unlock(&vdev->mutex);
		return -1;
	}

	vq->owner_thread = spdk_get_thread();
	pthread_mutex_unlock(&vdev->mutex);
	return i;
}

struct spdk_thread *
virtio_dev_queue_get_thread(struct virtio_dev *vdev, uint16_t index)
{
	struct virtqueue *vq;
	struct spdk_thread *thread = NULL;

	if (index >= vdev->max_queues) {
		SPDK_ERRLOG("given vq index %"PRIu16" exceeds max queue count %"PRIu16"\n",
			    index, vdev->max_queues);
		return NULL;
	}

	pthread_mutex_lock(&vdev->mutex);
	vq = vdev->vqs[index];
	if (vq != NULL) {
		thread = vq->owner_thread;
	}
	pthread_mutex_unlock(&vdev->mutex);

	return thread;
}

bool
virtio_dev_queue_is_acquired(struct virtio_dev *vdev, uint16_t index)
{
	return virtio_dev_queue_get_thread(vdev, index) != NULL;
}

void
virtio_dev_release_queue(struct virtio_dev *vdev, uint16_t index)
{
	struct virtqueue *vq = NULL;

	if (index >= vdev->max_queues) {
		SPDK_ERRLOG("given vq index %"PRIu16" exceeds max queue count %"PRIu16".\n",
			    index, vdev->max_queues);
		return;
	}

	pthread_mutex_lock(&vdev->mutex);
	vq = vdev->vqs[index];
	if (vq == NULL) {
		SPDK_ERRLOG("virtqueue at index %"PRIu16" is not initialized.\n", index);
		pthread_mutex_unlock(&vdev->mutex);
		return;
	}

	assert(vq->owner_thread == spdk_get_thread());
	vq->owner_thread = NULL;
	pthread_mutex_unlock(&vdev->mutex);
}

void
virtio_dev_read_dev_config(struct virtio_dev *dev, size_t offset,
			   void *dst, int length)
{
	virtio_dev_backend_ops(dev)->read_dev_cfg(dev, offset, dst, length);
}

void
virtio_dev_write_dev_config(struct virtio_dev *dev, size_t offset,
			    const void *src, int length)
{
	virtio_dev_backend_ops(dev)->write_dev_cfg(dev, offset, src, length);
}

void
virtio_dev_stop(struct virtio_dev *dev)
{
	virtio_dev_backend_ops(dev)->set_status(dev, VIRTIO_CONFIG_S_RESET);
	/* flush status write */
	virtio_dev_backend_ops(dev)->get_status(dev);
	virtio_free_queues(dev);
}

void
virtio_dev_set_status(struct virtio_dev *dev, uint8_t status)
{
	if (status != VIRTIO_CONFIG_S_RESET) {
		status |= virtio_dev_backend_ops(dev)->get_status(dev);
	}

	virtio_dev_backend_ops(dev)->set_status(dev, status);
}

uint8_t
virtio_dev_get_status(struct virtio_dev *dev)
{
	return virtio_dev_backend_ops(dev)->get_status(dev);
}

const struct virtio_dev_ops *
virtio_dev_backend_ops(struct virtio_dev *dev)
{
	return dev->backend_ops;
}

void
virtio_dev_dump_json_info(struct virtio_dev *hw, struct spdk_json_write_ctx *w)
{
	spdk_json_write_name(w, "virtio");
	spdk_json_write_object_begin(w);

	spdk_json_write_name(w, "vq_count");
	spdk_json_write_uint32(w, hw->max_queues);

	spdk_json_write_name(w, "vq_size");
	spdk_json_write_uint32(w, virtio_dev_backend_ops(hw)->get_queue_num(hw, 0));

	virtio_dev_backend_ops(hw)->dump_json_info(hw, w);

	spdk_json_write_object_end(w);
}

SPDK_LOG_REGISTER_COMPONENT("virtio_dev", SPDK_LOG_VIRTIO_DEV)
