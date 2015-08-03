/* Copyright (c) 2015 Cornell University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>
#include <rte_string_fns.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_connectal.h>

#include "sonic_rxtx.h"
#include "sonic_ethdev.h"
#include "sonic_logs.h"

#include "dmaManager.h"

#define SONIC_ALIGN 128

/*
 * Maximum number of Ring Descriptors.
 *
 * Since RDLEN/TDLEN should be multiple of 128 bytes, the number of ring
 * descriptors should meet the following condition:
 *      (num_ring_desc * sizeof(rx/tx descriptor)) % 128 == 0
 */
#define SONIC_MIN_RING_DESC 32
#define SONIC_MAX_RING_DESC 4096

static inline struct rte_mbuf *
rte_rxmbuf_alloc(struct rte_mempool *mp)
{
	struct rte_mbuf *m;

	m = __rte_mbuf_raw_alloc(mp);
	__rte_mbuf_sanity_check_raw(m, 0);
	return (m);
}

static const struct rte_memzone *
ring_dma_zone_reserve(struct rte_eth_dev *dev, const char *ring_name,
		      uint16_t queue_id, uint32_t ring_size, int socket_id)
{
	char z_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;

	snprintf(z_name, sizeof(z_name), "%s_%s_%d_%d",
			dev->driver->pci_drv.name, ring_name,
				dev->data->port_id, queue_id);
	mz = rte_memzone_lookup(z_name);
	if (mz)
		return mz;

#ifdef RTE_LIBRTE_XEN_DOM0
	return rte_memzone_reserve_bounded(z_name, ring_size,
			socket_id, 0, SONIC_ALIGN, RTE_PGSIZE_2M);
#else
	return rte_memzone_reserve_aligned(z_name, ring_size,
			socket_id, 0, SONIC_ALIGN);
#endif
}

static int __attribute__((cold))
sonic_alloc_rx_queue_mbufs(struct sonic_rx_queue *rxq)
{
	struct sonic_rx_entry *rxe = rxq->sw_ring;
	uint64_t dma_addr;
	unsigned i;

	/* Initialize software ring entries */
	for (i = 0; i < rxq->nb_rx_desc; i++) {
		struct rte_mbuf *mbuf = rte_rxmbuf_alloc(rxq->mb_pool);
		if (mbuf == NULL) {
			PMD_INIT_LOG(ERR, "RX mbuf alloc failed queue_id=%u",
				     (unsigned) rxq->queue_id);
			return (-ENOMEM);
		}

		rte_mbuf_refcnt_set(mbuf, 1);
		mbuf->next = NULL;
		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		mbuf->nb_segs = 1;
		mbuf->port = rxq->port_id;

        //FIXME: set dma address

		rxe[i].mbuf = mbuf;
	}

	return 0;
}

static void __attribute__((cold))
sonic_rx_queue_release_mbufs(struct sonic_rx_queue *rxq)
{
	unsigned i;

	if (rxq->sw_ring != NULL) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf != NULL &&
					rte_mbuf_refcnt_read(rxq->sw_ring[i].mbuf)) {
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
				rxq->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

//FIXME: memory leak
static void __attribute__((cold))
sonic_rx_queue_release(struct sonic_rx_queue *rxq)
{
    PMD_INIT_FUNC_TRACE();
    if (rxq != NULL) {
		sonic_rx_queue_release_mbufs(rxq);
        rte_free(rxq->sw_ring);
        rte_free(rxq);
    }
}

void __attribute__((cold))
sonic_dev_rx_queue_release(void *rxq)
{
	sonic_rx_queue_release(rxq);
}

static void __attribute__((cold))
sonic_tx_queue_release(struct sonic_tx_queue *txq)
{
    PMD_INIT_FUNC_TRACE();
    struct sonic_tx_queue *nq;
    if (txq == NULL)
        return;

    nq=txq;
    rte_free(nq->sw_ring);
}

void __attribute__((cold))
sonic_dev_tx_queue_release(void *txq)
{
	sonic_tx_queue_release(txq);
}

static void
sonic_reset_rx_queue(struct sonic_rx_queue *rxq)
{
	static const union sonic_rx_desc zeroed_desc = {{0}};
	unsigned i;

	/* Zero out HW ring memory */
	for (i = 0; i < rxq->nb_rx_desc; i++) {
		rxq->rx_ring[i] = zeroed_desc;
	}

}

static void
sonic_reset_tx_queue(struct sonic_tx_queue *txq)
{
    PMD_INIT_FUNC_TRACE();
    PMD_TX_LOG(DEBUG, "Reset TX queue not implemented!");
}

int __attribute__((cold))
sonic_dev_rx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp)
{
    PMD_INIT_FUNC_TRACE();
    const struct rte_memzone *rz;
    struct sonic_rx_queue *rxq;
    uint32_t size;

    // access to hw through connectal.so
    if (dev->data->rx_queues[queue_idx] != NULL) {
        sonic_dev_rx_queue_release(dev->data->rx_queues[queue_idx]);
        dev->data->rx_queues[queue_idx] = NULL;
    }

    /* First allocate RX queue data structure */
    rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct sonic_rx_queue),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (rxq == NULL)
        return -ENOMEM;
    rxq->mb_pool = mp;
    rxq->nb_rx_desc = nb_desc;
    rxq->queue_id = queue_idx;
    rxq->port_id = dev->data->port_id;

    /*
     * Allocate RX ring hardware descriptors.
     */
    size = sizeof(union sonic_rx_desc) * SONIC_MAX_RING_DESC;
    PMD_RX_LOG(DEBUG, "allocated queue %p, nb_desc=%d, desc_ring size=%d",
            rxq, rxq->nb_rx_desc, size);
    rz = ring_dma_zone_reserve(dev, "rx_ring", queue_idx, size, socket_id);
    if (rz == NULL) {
        sonic_dev_rx_queue_release(rxq);
        return -ENOMEM;
    }

    /*
     * Zero init all the descriptors in the ring.
     */
    memset (rz->addr, 0, size);

    rxq->rx_ring_phys_addr = (uint64_t)rz->phys_addr;
    rxq->rx_ring = (union sonic_rx_desc *)rz->addr;

    PMD_RX_LOG(DEBUG, "rx_ring_phys_addr=0x%lx, rx_ring=%p",
            rxq->rx_ring_phys_addr, rxq->rx_ring);

    /*
     * Allocate software ring
     */
    rxq->sw_ring = rte_zmalloc_socket("rxq->sw_ring",
                               sizeof(struct sonic_rx_entry) * nb_desc,
                               RTE_CACHE_LINE_SIZE, socket_id);
    if (rxq->sw_ring==NULL) {
        sonic_rx_queue_release(rxq);
        return (-ENOMEM);
    }
    PMD_INIT_LOG(DEBUG, "sw_ring=%p hw_ring=%p, dma_addr=0x%"PRIx64,
                 rxq->sw_ring, rxq->rx_ring, rxq->rx_ring_phys_addr);

    rxq->dev = dev;

    dev->data->rx_queues[queue_idx] = rxq;
    sonic_reset_rx_queue(rxq);

    // Loopback queue
    //struct pmd_internals *internals = dev->data->dev_private;
    //dev->data->rx_queues[queue_idx] = &internals->rx_sonic_queues[queue_idx];
    return 0;
}

int __attribute__((cold))
sonic_dev_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_txconf *tx_conf)
{
    const struct rte_memzone *tz;
    struct sonic_tx_queue *txq;
    uint32_t size;

    PMD_INIT_FUNC_TRACE();
    /* Get access to connectal via so */

    PMD_INIT_LOG(DEBUG, "Create TX Queue at Socket %d", socket_id);
	/* Free memory prior to re-allocation if needed */
	if (dev->data->tx_queues[queue_idx] != NULL) {
		sonic_tx_queue_release(dev->data->tx_queues[queue_idx]);
		dev->data->tx_queues[queue_idx] = NULL;
    }

	/* First allocate the tx queue data structure */
	txq = rte_zmalloc_socket("ethdev TX queue",
                            sizeof(struct sonic_tx_queue),
							RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL)
		return (-ENOMEM);

	/*
	 * Allocate TX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	size = sizeof(union sonic_tx_desc) * SONIC_MAX_RING_DESC;
	tz = ring_dma_zone_reserve(dev, "tx_ring", queue_idx,
					size, socket_id);
	if (tz == NULL) {
		sonic_tx_queue_release(txq);
		return (-ENOMEM);
	}

	txq->nb_tx_desc = nb_desc;
	txq->queue_id = queue_idx;
	txq->port_id = dev->data->port_id;
	txq->tx_ring_phys_addr = (uint64_t) tz->phys_addr;
	txq->tx_ring = (union sonic_tx_desc *) tz->addr;

	/* Allocate software ring */
	txq->sw_ring = rte_zmalloc_socket("txq->sw_ring",
				   sizeof(struct sonic_tx_entry) * nb_desc,
				   RTE_CACHE_LINE_SIZE, socket_id);
	if (txq->sw_ring == NULL) {
		sonic_tx_queue_release(txq);
		return (-ENOMEM);
	}
	PMD_INIT_LOG(DEBUG, "txq=%p, sw_ring=%p hw_ring=%p dma_addr=0x%"PRIx64,
		         txq, txq->sw_ring, txq->tx_ring, txq->tx_ring_phys_addr);

    txq->dev = dev;
	dev->data->tx_queues[queue_idx] = txq;
	sonic_reset_tx_queue(txq);

    //Loopback queue
	//struct pmd_internals *internals = dev->data->dev_private;
	//dev->data->tx_queues[queue_idx] = &internals->tx_sonic_queues[queue_idx];

    return 0;
}

/*
 * Start Receive Units for specified queue.
 */
int __attribute__((cold))
sonic_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	struct sonic_rx_queue *rxq;
	if (rx_queue_id < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[rx_queue_id];

		/* Allocate buffers for descriptor rings */
		if (sonic_alloc_rx_queue_mbufs(rxq) != 0) {
			PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
				     rx_queue_id);
			return -1;
		}
        PMD_RX_LOG(DEBUG, "Enable RX on connectal");
    } else {
        return -1;
    }
    return 0;
}

/*
 * Stop Receive Units for specified queue.
 */
int __attribute__((cold))
sonic_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	struct sonic_rx_queue *rxq;
	if (rx_queue_id < dev->data->nb_rx_queues) {
		rxq = dev->data->rx_queues[rx_queue_id];
        PMD_RX_LOG(DEBUG, "Disable RX on connectal");
		sonic_rx_queue_release_mbufs(rxq);
		sonic_reset_rx_queue(rxq);
	} else {
		return -1;
    }
    return 0;
}

/*
 * Start Transmit Units for specified queue.
 */
int __attribute__((cold))
sonic_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	struct sonic_tx_queue *txq;
	if (tx_queue_id < dev->data->nb_tx_queues) {
		txq = dev->data->tx_queues[tx_queue_id];
        PMD_TX_LOG(DEBUG, "Enable TX on connectal");
	} else {
		return -1;
    }
    return 0;
}

/*
 * Stop Transmit Units for specified queue.
 */
int __attribute__((cold))
sonic_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
	struct sonic_tx_queue *txq;
	if (tx_queue_id < dev->data->nb_tx_queues) {
		txq = dev->data->tx_queues[tx_queue_id];
        PMD_TX_LOG(DEBUG, "send command to hardware to stop tx");

        //FIXME: memory leak on mbuf in txq
        sonic_reset_tx_queue(txq);
	} else {
		return -1;
    }
    return 0;
}

/*
 * Enable receive unit.
 */
int
eth_sonic_rx_init(struct rte_eth_dev *dev)
{
    uint16_t i;
    PMD_INIT_FUNC_TRACE();

    for (i = 0; i < dev->data->nb_rx_queues; i++) {
        // build sglist and send to FPGA
    }
    return 0;
}

/*
 * Enable transmit unit.
 */
void
eth_sonic_tx_init(struct rte_eth_dev *dev)
{
    uint16_t i;
    PMD_INIT_FUNC_TRACE();
    struct sonic_tx_queue *txq;

    /* Setup MMU in connectal */
    for (i=0; i < dev->data->nb_tx_queues; i++) {
        // build sglist and send to FPGA.
        txq = dev->data->tx_queues[i];
        PMD_INIT_LOG(DEBUG, "sw_ring=%p hw_ring=%p dma_addr=0x%"PRIx64,
                 txq->sw_ring, txq->tx_ring, txq->tx_ring_phys_addr);
    }
}

/*
 * receive burst of packets from hardware
 */
uint16_t
rx_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	     uint16_t nb_pkts)
{
    void **ptrs = (void *)&rx_pkts[0];
	struct sonic_rx_queue *r = rx_queue;
    connectal->poll();
	return 0;
}

/*
 * send burst of packets to hardware
 */
uint16_t
tx_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	     uint16_t nb_pkts)
{
	void **ptrs = (void *)&tx_pkts[0];
	struct sonic_tx_queue *r = tx_queue;
    /** send to nic */
    uint64_t buf_dma_addr;
    uint32_t pkt_len;
    int i;

    for (i=0; i<nb_pkts; ++i, ++tx_pkts) {
        buf_dma_addr = RTE_MBUF_DATA_DMA_ADDR(*tx_pkts);
        pkt_len = (*tx_pkts)->data_len;
        PMD_INIT_LOG(DEBUG, "tx_xmit: %d dma_addr=0x%"PRIx64" pkt_len=%d", i, buf_dma_addr, pkt_len);
        connectal->tx_send_pa(buf_dma_addr, pkt_len);
    }

	return i;
}
