/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
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

#ifndef SPDK_VIRTIO_H
#define SPDK_VIRTIO_H

#include "spdk/stdinc.h"

#include <linux/virtio_ring.h>
#include <linux/virtio_pci.h>
#include <linux/virtio_config.h>

#include "spdk_internal/log.h"
#include "spdk/likely.h"
#include "spdk/queue.h"
#include "spdk/json.h"
#include "spdk/io_channel.h"

/**
 * The maximum virtqueue size is 2^15. Use that value as the end of
 * descriptor chain terminator since it will never be a valid index
 * in the descriptor table. This is used to verify we are correctly
 * handling vq_free_cnt.
 */
#define VQ_RING_DESC_CHAIN_END 32768

#define SPDK_VIRTIO_MAX_VIRTQUEUES 0x100

/* Extra status define for readability */
#define VIRTIO_CONFIG_S_RESET 0

struct virtio_dev_ops;

struct virtio_dev {
	struct virtqueue **vqs;

	/** Name of this virtio dev set by backend */
	char		*name;

	/** Max number of queues the host supports. */
	uint16_t	max_queues;

	/** Common device & guest features. */
	uint64_t	negotiated_features;

	int		is_hw;

	/** Modern/legacy virtio device flag. */
	uint8_t		modern;

	/** Mutex for asynchronous virtqueue-changing operations. */
	pthread_mutex_t	mutex;

	/** Backend-specific callbacks. */
	const struct virtio_dev_ops *backend_ops;

	/** Context for the backend ops */
	void		*ctx;

	TAILQ_ENTRY(virtio_dev) tailq;
};

struct virtio_dev_ops {
	void (*read_dev_cfg)(struct virtio_dev *hw, size_t offset,
			     void *dst, int len);
	void (*write_dev_cfg)(struct virtio_dev *hw, size_t offset,
			      const void *src, int len);
	uint8_t (*get_status)(struct virtio_dev *hw);
	void (*set_status)(struct virtio_dev *hw, uint8_t status);

	/**
	 * Get device features. The features might be already
	 * negotiated with driver (guest) features.
	 */
	uint64_t (*get_features)(struct virtio_dev *vdev);

	/**
	 * Negotiate and set device features.
	 * The negotiation can fail with return code -1.
	 * This function should also set vdev->negotiated_features field.
	 */
	int (*set_features)(struct virtio_dev *vdev, uint64_t features);

	/** Destruct virtio device */
	void (*destruct_dev)(struct virtio_dev *vdev);

	uint16_t (*get_queue_num)(struct virtio_dev *hw, uint16_t queue_id);
	int (*setup_queue)(struct virtio_dev *hw, struct virtqueue *vq);
	void (*del_queue)(struct virtio_dev *hw, struct virtqueue *vq);
	void (*notify_queue)(struct virtio_dev *hw, struct virtqueue *vq);

	void (*dump_json_config)(struct virtio_dev *hw, struct spdk_json_write_ctx *w);
};

struct vq_desc_extra {
	void *cookie;
	uint16_t ndescs;
};

struct virtqueue {
	struct virtio_dev *vdev; /**< owner of this virtqueue */
	struct vring vq_ring;  /**< vring keeping desc, used and avail */
	/**
	 * Last consumed descriptor in the used table,
	 * trails vq_ring.used->idx.
	 */
	uint16_t vq_used_cons_idx;
	uint16_t vq_nentries;  /**< vring desc numbers */
	uint16_t vq_free_cnt;  /**< num of desc available */
	uint16_t vq_avail_idx; /**< sync until needed */

	void *vq_ring_virt_mem;  /**< virtual address of vring */
	unsigned int vq_ring_size;

	uint64_t vq_ring_mem; /**< physical address of vring */

	/**
	 * Head of the free chain in the descriptor table. If
	 * there are no free descriptors, this will be set to
	 * VQ_RING_DESC_CHAIN_END.
	 */
	uint16_t  vq_desc_head_idx;

	/**
	 * Tail of the free chain in desc table. If
	 * there are no free descriptors, this will be set to
	 * VQ_RING_DESC_CHAIN_END.
	 */
	uint16_t  vq_desc_tail_idx;
	uint16_t  vq_queue_index;   /**< PCI queue index */
	uint16_t  *notify_addr;

	/** Thread that's polling this queue. */
	struct spdk_thread *owner_thread;

	uint16_t req_start;
	uint16_t req_end;

	struct vq_desc_extra vq_descx[0];
};

enum spdk_virtio_desc_type {
	SPDK_VIRTIO_DESC_RO = 0, /**< Read only */
	SPDK_VIRTIO_DESC_WR = VRING_DESC_F_WRITE, /**< Write only */
	/* TODO VIRTIO_DESC_INDIRECT */
};

struct virtio_driver {
	TAILQ_HEAD(, virtio_dev) scsi_devs;
};

extern struct virtio_driver g_virtio_driver;

/** Context for creating PCI virtio_devs */
struct virtio_pci_ctx;

/**
 * Callback for creating virtio_dev from a PCI device.
 * The first param is the PCI context to be associated with virtio_dev.
 * \return 0 on success, -1 on error.
 */
typedef int (*virtio_pci_create_cb)(struct virtio_pci_ctx *pci_ctx);

uint16_t virtio_recv_pkts(struct virtqueue *vq, void **io, uint32_t *len, uint16_t io_cnt);

/**
 * Start a new request on the current vring head position. The request will
 * be bound to given opaque cookie object. All previous requests will be
 * still kept in a ring until they are flushed or the request is aborted.
 * If a previous request is empty (no descriptors have been added) this call
 * will overwrite it. The device owning given virtqueue must be started.
 *
 * \param vq virtio queue
 * \param cookie opaque object to bind with this request. Once the request
 * is sent, processed and a response is received, the same object will be
 * returned to the user calling the virtio poll API.
 * \param iovcnt number of required iovectors for the request. This can be
 * higher than than the actual number of descriptors to be added.
 * \return 0 on success or negative errno otherwise. If not enough iovectors
 * are available, -ENOSPC is returned.
 */
int virtqueue_req_start(struct virtqueue *vq, void *cookie, int iovcnt);

/**
 * Flush a virtqueue. This will make the host device see and process all
 * previously queued requests. An interrupt might be automatically sent if
 * the host device expects it. The device owning given virtqueue must be started.
 *
 * \param vq virtio queue
 */
void virtqueue_req_flush(struct virtqueue *vq);

/**
 * Abort the very last request in a virtqueue. This will restore virtqueue
 * state to the point before the last request was created. Note that this
 * is only effective if a queue hasn't been flushed yet.  The device owning
 * given virtqueue must be started.
 *
 * \param vq virtio queue
 */
void virtqueue_req_abort(struct virtqueue *vq);

/**
 * Add iovec chain to the last created request. This call does not provide any
 * error-checking. The caller has to ensure that he doesn't add more iovs than
 * what was specified during request creation. The device owning given virtqueue
 * must be started.
 *
 * \param vq virtio queue
 * \param iovs iovec array
 * \param iovcnt number of iovs in iovec array
 * \param desc_type type of all given iovectors
 */
void virtqueue_req_add_iovs(struct virtqueue *vq, struct iovec *iovs, uint16_t iovcnt,
			    enum spdk_virtio_desc_type desc_type);

/**
 * Construct a virtio device.  The device will be in stopped state by default.
 * Before doing any I/O, it has to be manually started via \c virtio_dev_restart.
 *
 * \param vdev memory for virtio device, must be zeroed
 * \param ops backend callbacks
 * \param ctx argument for the backend callbacks
 */
int virtio_dev_construct(struct virtio_dev *vdev, const struct virtio_dev_ops *ops,
			 void *ctx);

/**
 * Notify the host to start processing this virtio device.  This is
 * a blocking call that won't return until the host has started.
 * This call will also allocate virtqueues and renegotiate feature flags.
 *
 * \param vdev virtio device
 * \param req_features features this driver supports. A VIRTIO_F_VERSION_1
 * flag will be automatically appended, as legacy devices are not supported.
 */
int virtio_dev_restart(struct virtio_dev *vdev, uint64_t req_features);

/**
 * Stop the host from processing the device.  This is a blocking call
 * that won't return until all outstanding I/O has been processed on
 * the host (virtio device) side.
 *
 * \param vdev virtio device
 */
void virtio_dev_stop(struct virtio_dev *vdev);

/**
 * Destruct a virtio device.  Note that it must be in the stopped state.
 * The virtio_dev should be manually freed afterwards.
 *
 * \param vdev virtio device
 */
void virtio_dev_destruct(struct virtio_dev *vdev);

/**
 * Bind a virtqueue with given index to the current thread;
 *
 * This function is thread-safe.
 *
 * \param vdev vhost device
 * \param index virtqueue index
 * \return 0 on success, -1 in case a virtqueue with given index either
 * does not exists or is already acquired.
 */
int virtio_dev_acquire_queue(struct virtio_dev *vdev, uint16_t index);

/**
 * Look for unused queue and bind it to the current thread.  This will
 * scan the queues in range from *start_index* (inclusive) up to
 * vdev->max_queues (exclusive).
 *
 * This function is thread-safe.
 *
 * \param vdev vhost device
 * \param start_index virtqueue index to start looking from
 * \return index of acquired queue or -1 in case no unused queue in given range
 * has been found
 */
int32_t virtio_dev_find_and_acquire_queue(struct virtio_dev *vdev, uint16_t start_index);

/**
 * Get thread that acquired given virtqueue.
 *
 * This function is thread-safe.
 *
 * \param vdev vhost device
 * \param index index of virtqueue
 * \return thread that acquired given virtqueue. If the queue is unused
 * or doesn't exist a NULL is returned.
 */
struct spdk_thread *virtio_dev_queue_get_thread(struct virtio_dev *vdev, uint16_t index);

/**
 * Check if virtqueue with given index is acquired.
 *
 * This function is thread-safe.
 *
 * \param vdev vhost device
 * \param index index of virtqueue
 * \return virtqueue acquire status. in case of invalid index *false* is returned.
 */
bool virtio_dev_queue_is_acquired(struct virtio_dev *vdev, uint16_t index);

/**
 * Release previously acquired queue.
 *
 * This function must be called from the thread that acquired the queue.
 *
 * \param vdev vhost device
 * \param index index of virtqueue to release
 */
void virtio_dev_release_queue(struct virtio_dev *vdev, uint16_t index);

/**
 * Get Virtio status flags.
 *
 * \param vdev virtio device
 */
uint8_t virtio_dev_get_status(struct virtio_dev *vdev);

/**
 * Set Virtio status flag.  The flags have to be set in very specific order
 * defined the VIRTIO 1.0 spec section 3.1.1. To unset the flags, stop the
 * device or set \c VIRTIO_CONFIG_S_RESET status flag. There is no way to
 * unset only particular flags.
 *
 * \param vdev virtio device
 * \param flag flag to set
 */
void virtio_dev_set_status(struct virtio_dev *vdev, uint8_t flag);

/**
 * Write raw data into the device config at given offset.  This call does not
 * provide any error checking.
 *
 * \param vdev virtio device
 * \param offset offset in bytes
 * \param src pointer to data to copy from
 * \param len length of data to copy in bytes
 */
void virtio_dev_write_dev_config(struct virtio_dev *vdev, size_t offset, const void *src, int len);

/**
 * Read raw data from the device config at given offset.  This call does not
 * provide any error checking.
 *
 * \param vdev virtio device
 * \param offset offset in bytes
 * \param dst pointer to buffer to copy data into
 * \param len length of data to copy in bytes
 */
void virtio_dev_read_dev_config(struct virtio_dev *vdev, size_t offset, void *dst, int len);

/**
 * Get backend-specific ops for given device.
 *
 * \param vdev virtio device
 */
const struct virtio_dev_ops *virtio_dev_backend_ops(struct virtio_dev *vdev);

/**
 * Check if the device has negotiated given feature bit.
 *
 * \param vdev virtio device
 * \param bit feature bit
 */
static inline bool
virtio_dev_has_feature(struct virtio_dev *vdev, uint64_t bit)
{
	return !!(vdev->negotiated_features & (1ULL << bit));
}

/**
 * Dump all device specific information into given json stream.
 *
 * \param vdev virtio device
 * \param w json stream
 */
void virtio_dev_dump_json_config(struct virtio_dev *vdev, struct spdk_json_write_ctx *w);

/**
 * Enumerate all PCI Virtio devices on the system.
 *
 * \param enum_cb a function to be called for each valid PCI device.
 * \return if a virtio_dev is has been created, the callback should return 0.
 * Returning any other value will cause the PCI context to be freed,
 * making it unusable.
 */
int virtio_pci_scsi_dev_enumerate(virtio_pci_create_cb enum_cb);

/**
 * Connect to a vhost-user device and init corresponding virtio_dev struct.
 * The virtio_dev will have to be freed with \c virtio_dev_free.
 *
 * \param vdev preallocated vhost device struct to operate on
 * \param name name of this virtio device
 * \param path path to the Unix domain socket of the vhost-user device
 * \param requested_queues maximum number of request queues that this
 * device will support
 * \param queue_size size of each of the queues
 * \param fixed_queue_num number of queues preceeding the first
 * request queue. For Virtio-SCSI this is equal to 2, as there are
 * additional event and control queues.
 * \return virtio device
 */
int virtio_user_dev_init(struct virtio_dev *vdev, const char *name, const char *path,
			 uint16_t requested_queues, uint32_t queue_size,
			 uint16_t fixed_queue_num);

/**
 * Initialize a virtio_dev for the given PCI device.
 * The virtio_dev will try to use \c SPDK_VIRTIO_MAX_VIRTQUEUES queues by
 * default and might fail to start. It is advised to overwrite the
 * `virtio_dev->max_queues` field manually starting the device.
 * The virtio_dev has to be freed with \c virtio_dev_destruct.
 *
 * \param vdev preallocated vhost device struct to operate on
 * \param name name of this virtio device
 * \param pci_ctx context of the PCI device
 * \return 0 on success, -1 on error.
 */
int virtio_pci_dev_init(struct virtio_dev *vdev, const char *name,
			struct virtio_pci_ctx *pci_ctx);

#endif /* SPDK_VIRTIO_H */
