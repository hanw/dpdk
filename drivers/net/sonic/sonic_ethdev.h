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

#include "sonic_logs.h"

#ifndef _SONIC_ETHDEV_H_

struct pmd_internals;

struct sonic_queue {
	struct pmd_internals *internals;

	struct rte_mempool *mb_pool;
	struct rte_mbuf *dummy_packet;

	rte_atomic64_t rx_pkts;
	rte_atomic64_t tx_pkts;
	rte_atomic64_t err_pkts;
};

struct pmd_internals {
	unsigned packet_size;
	unsigned numa_node;

	unsigned nb_rx_queues;
	unsigned nb_tx_queues;

	struct sonic_queue rx_sonic_queues[1];
	struct sonic_queue tx_sonic_queues[1];
};

/*
 * RX/TX function prototypes
 */

void sonic_dev_rx_queue_release(void *rxq);

void sonic_dev_tx_queue_release(void *txq);

int  sonic_dev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, unsigned int socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mb_pool);

int  sonic_dev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf);

int sonic_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id);

int sonic_dev_rx_queue_stop(struct rte_eth_dev *dev, uint16_t rx_queue_id);

int sonic_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id);

int sonic_dev_tx_queue_stop(struct rte_eth_dev *dev, uint16_t tx_queue_id);

#endif /* _SONIC_ETHDEV_H_ */
