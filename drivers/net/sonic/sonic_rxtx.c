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

#include "sonic_ethdev.h"
#include "sonic_rxtx.h"
#include "sonic_logs.h"

int __attribute__((cold))
sonic_dev_rx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mb_pool)
{
    PMD_RX_LOG(DEBUG, "rx_queue_setup\n");
	struct rte_mbuf *dummy_packet;
	struct pmd_internals *internals;
	unsigned packet_size;

	if ((dev == NULL) || (mb_pool == NULL))
		return -EINVAL;

	if (queue_idx != 0)
		return -ENODEV;

	internals = dev->data->dev_private;
	packet_size = internals->packet_size;

	internals->rx_sonic_queues[queue_idx].mb_pool = mb_pool;
	dev->data->rx_queues[queue_idx] =
		&internals->rx_sonic_queues[queue_idx];
	dummy_packet = rte_zmalloc_socket(NULL,
			packet_size, 0, internals->numa_node);
	if (dummy_packet == NULL)
		return -ENOMEM;

	internals->rx_sonic_queues[queue_idx].internals = internals;
	internals->rx_sonic_queues[queue_idx].dummy_packet = dummy_packet;
    return 0;
}

static void __attribute__((cold))
sonic_rx_queue_release(struct sonic_queue *rxq)
{
    PMD_RX_LOG(DEBUG, "rx_queue_release\n");
    struct sonic_queue *nq;
    if (rxq == NULL)
        return;

    nq=rxq;
    rte_free(nq->dummy_packet);
}

void __attribute__((cold))
sonic_dev_rx_queue_release(void *rxq)
{
	sonic_rx_queue_release(rxq);
}

int __attribute__((cold))
sonic_dev_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_txconf *tx_conf)
{
    PMD_TX_LOG(DEBUG, "tx_queue_setup\n");
	struct rte_mbuf *dummy_packet;
	struct pmd_internals *internals;
	unsigned packet_size;

	if (dev == NULL)
		return -EINVAL;

	if (queue_idx != 0)
		return -ENODEV;

	internals = dev->data->dev_private;
	packet_size = internals->packet_size;

	dev->data->tx_queues[queue_idx] =
		&internals->tx_sonic_queues[queue_idx];
	dummy_packet = rte_zmalloc_socket(NULL,
			packet_size, 0, internals->numa_node);
	if (dummy_packet == NULL)
		return -ENOMEM;

	internals->tx_sonic_queues[queue_idx].internals = internals;
	internals->tx_sonic_queues[queue_idx].dummy_packet = dummy_packet;
    return 0;
}

static void __attribute__((cold))
sonic_tx_queue_release(struct sonic_queue *txq)
{
    PMD_TX_LOG(DEBUG, "tx_queue_release\n");
    struct sonic_queue *nq;
    if (txq == NULL)
        return;

    nq=txq;
    rte_free(nq->dummy_packet);
}

void __attribute__((cold))
sonic_dev_tx_queue_release(void *txq)
{
	sonic_tx_queue_release(txq);
}

/*
 * Start Receive Units for specified queue.
 */
int __attribute__((cold))
sonic_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t queue_idx)
{
    PMD_RX_LOG(DEBUG, "rx_queue_start\n");
    return 0;
}

/*
 * Stop Receive Units for specified queue.
 */
int __attribute__((cold))
sonic_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t queue_idx)
{
    PMD_RX_LOG(DEBUG, "rx_queue_stop\n");
    return 0;
}

/*
 * Start Transmit Units for specified queue.
 */
int __attribute__((cold))
sonic_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t queue_idx)
{
    PMD_TX_LOG(DEBUG, "tx_queue_start\n");
    return 0;
}

/*
 * Stop Transmit Units for specified queue.
 */
int __attribute__((cold))
sonic_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t queue_idx)
{
    PMD_TX_LOG(DEBUG, "tx_queue_stop\n");
    return 0;
}


