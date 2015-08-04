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
#include <sys/file.h>
#include <sys/mman.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <dlfcn.h>

#include <rte_interrupts.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_dev.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_dev.h>
#include <rte_kvargs.h>
#include <rte_connectal.h> /** provides struct connectal_ops *connectal */

#include "sonic_rxtx.h"
#include "sonic_ethdev.h"
#include "sonic_logs.h"

#define LENGTH (1024UL * 1024 * 1024)

enum dev_action{
	DEV_CREATE,
	DEV_ATTACH
};

static struct ether_addr eth_addr = { .addr_bytes = {0} };
static const char *drivername = "SONIC PMD";
static struct rte_eth_link pmd_link = {
	.link_speed = 10000,
	.link_duplex = ETH_LINK_FULL_DUPLEX,
	.link_status = 0
};

static struct eth_driver rte_sonic_pmd = {
	.pci_drv = {
		.name = "rte_sonic_pmd",
		.drv_flags = RTE_PCI_DRV_DETACHABLE,
	},
};

static int  sonic_dev_configure(struct rte_eth_dev *dev);
static int  sonic_dev_start(struct rte_eth_dev *dev);
static void sonic_dev_stop(struct rte_eth_dev *dev);
static void sonic_dev_close(struct rte_eth_dev *dev);
static void sonic_dev_stats_get(struct rte_eth_dev *dev,
				struct rte_eth_stats *stats);
static void sonic_dev_stats_reset(struct rte_eth_dev *dev);
static void sonic_dev_info_get(struct rte_eth_dev *dev,
			       struct rte_eth_dev_info *dev_info);

static int sonic_dev_link_update(struct rte_eth_dev *dev __rte_unused,
            int wait_to_complete __rte_unused);

static const struct eth_dev_ops ops = {
	.dev_configure        = sonic_dev_configure,
	.dev_start            = sonic_dev_start,
	.dev_stop             = sonic_dev_stop,
	.dev_set_link_up      = NULL,
	.dev_set_link_down    = NULL,
	.dev_close            = sonic_dev_close,
	.link_update          = sonic_dev_link_update,
	.stats_get            = sonic_dev_stats_get,
	.stats_reset          = sonic_dev_stats_reset,
	.dev_infos_get        = sonic_dev_info_get,
	.rx_queue_start	      = sonic_dev_rx_queue_start,
	.rx_queue_stop        = sonic_dev_rx_queue_stop,
	.tx_queue_start	      = sonic_dev_tx_queue_start,
	.tx_queue_stop        = sonic_dev_tx_queue_stop,
	.rx_queue_setup       = sonic_dev_rx_queue_setup,
	.rx_queue_release     = sonic_dev_rx_queue_release,
	.rx_queue_count       = NULL,
	.rx_descriptor_done   = NULL,
	.tx_queue_setup       = sonic_dev_tx_queue_setup,
	.tx_queue_release     = sonic_dev_tx_queue_release,
};

static int
sonic_dev_configure(struct rte_eth_dev *dev)
{
    PMD_INIT_FUNC_TRACE();
    char filepath[128];
	struct pmd_internals *internals;
	if (dev == NULL)
		return;
	internals = dev->data->dev_private;

    rte_eal_hugepage_path(filepath, sizeof(filepath), 0);
    int fd = open(filepath, O_CREAT | O_RDWR, 0755);

    void *va = NULL;
    va = rte_zmalloc("dummy", 1000, 8);
    phys_addr_t pa = rte_malloc_virt2phy(va);
    fprintf(stderr, "va=%p, pa=0x%lx\n", va, pa);

    uint64_t base_pa = get_base_phys_addr();

    uint64_t offset = pa - base_pa;
    fprintf(stderr, "offset=0x%lx\n", offset);

    if (connectal->dma_init) {
        connectal->dma_init(fd, base_pa, LENGTH);
    }
    return 0;
}

/*
 * Configure device link speed and setup link.
 * It returns 0 on success.
 */
static int
sonic_dev_start(struct rte_eth_dev *dev)
{
    int ret;
    PMD_INIT_FUNC_TRACE();
	if (dev == NULL)
		return -EINVAL;

    // check if communication with FPGA yields magic number.

    PMD_INIT_LOG(DEBUG, "start device on port %d", dev->data->port_id);
    eth_sonic_tx_init(dev);

    ret = eth_sonic_rx_init(dev);
    if (ret) {
        PMD_INIT_LOG(ERR, "Unable to initialize Rx hardware");
        //sonic_dev_clear_queues(dev); //FIXME: fix memory leak
        return ret;
    }
	dev->data->dev_link.link_status = 1;
    return 0;
}

/*
 * Stop device: disable rx and tx functions to allow for reconfiguring.
 */
static void
sonic_dev_stop(struct rte_eth_dev *dev)
{
    PMD_INIT_FUNC_TRACE();
	if (dev == NULL)
		return;

	dev->data->dev_link.link_status = 0;
}

/*
 * Reest and stop device.
 */
static void
sonic_dev_close(struct rte_eth_dev *dev)
{
    PMD_INIT_FUNC_TRACE();
}

/*
 * This function is based on sonic_update_stats_counters() in base/sonic.c
 */
static void
sonic_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
    PMD_INIT_FUNC_TRACE();
	unsigned i;
	unsigned long rx_total = 0, tx_total = 0, tx_err_total = 0;
	const struct pmd_internals *internal = dev->data->dev_private;

	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS &&
			i < internal->nb_rx_queues; i++) {
		stats->q_ipackets[i] = internal->rx_sonic_queues[i].rx_pkts.cnt;
		rx_total += stats->q_ipackets[i];
	}

	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS &&
			i < internal->nb_tx_queues; i++) {
		stats->q_opackets[i] = internal->tx_sonic_queues[i].tx_pkts.cnt;
		stats->q_errors[i] = internal->tx_sonic_queues[i].err_pkts.cnt;
		tx_total += stats->q_opackets[i];
		tx_err_total += stats->q_errors[i];
	}

	stats->ipackets = rx_total;
	stats->opackets = tx_total;
	stats->oerrors = tx_err_total;
}

static void
sonic_dev_stats_reset(struct rte_eth_dev *dev)
{
    PMD_INIT_FUNC_TRACE();
	unsigned i;
	struct pmd_internals *internal = dev->data->dev_private;
	for (i = 0; i < internal->nb_rx_queues; i++)
		internal->rx_sonic_queues[i].rx_pkts.cnt = 0;
	for (i = 0; i < internal->nb_tx_queues; i++) {
		internal->tx_sonic_queues[i].tx_pkts.cnt = 0;
		internal->tx_sonic_queues[i].err_pkts.cnt = 0;
	}
}

static void
sonic_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
    PMD_INIT_FUNC_TRACE();
	struct pmd_internals *internals;

	if ((dev == NULL) || (dev_info == NULL))
		return;

	internals = dev->data->dev_private;
	dev_info->driver_name = drivername;
	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_pktlen = (uint32_t)-1;
	dev_info->max_rx_queues = (uint16_t)internals->nb_rx_queues;
	dev_info->max_tx_queues = (uint16_t)internals->nb_tx_queues;
	dev_info->min_rx_bufsize = 0;
	dev_info->pci_dev = NULL;

}

static int
sonic_dev_link_update(struct rte_eth_dev *dev __rte_unused,
		int wait_to_complete __rte_unused) {
    PMD_INIT_FUNC_TRACE();
    return 0;
}

static int
rte_sonic_pmd_init(const char *name, const char *params)
{
	PMD_INIT_FUNC_TRACE();
    const unsigned nb_rx_queues = 1;
    const unsigned nb_tx_queues = 1;
	struct rte_eth_dev_data *data = NULL;
	struct rte_pci_device *pci_dev = NULL;
	struct pmd_internals *internals = NULL;
	struct rte_eth_dev *eth_dev = NULL;
    unsigned i;
	unsigned numa_node;
	unsigned packet_size = 64;
	int ret;

	if (name == NULL)
		return -EINVAL;

	numa_node = rte_socket_id();

	/* now do all data allocation - for eth_dev structure, dummy pci driver
	 * and internal (private) data
	 */
	data = rte_zmalloc_socket(name, sizeof(*data), 0, numa_node);
	if (data == NULL)
		goto error;

	pci_dev = rte_zmalloc_socket(name, sizeof(*pci_dev), 0, numa_node);
	if (pci_dev == NULL)
		goto error;

	internals = rte_zmalloc_socket(name, sizeof(*internals), 0, numa_node);
	if (internals == NULL)
		goto error;

	/* reserve an ethdev entry */
	eth_dev = rte_eth_dev_allocate(name, RTE_ETH_DEV_VIRTUAL);
	if (eth_dev == NULL)
		goto error;

	/* now put it all together
	 * - store queue data in internals,
	 * - store numa_node info in pci_driver
	 * - point eth_dev_data to internals and pci_driver
	 * - and point eth_dev structure to new eth_dev_data structure
	 */
	/* NOTE: we'll replace the data element, of originally allocated eth_dev
	 * so the nulls are local per-process */
    RTE_LOG(DEBUG, PMD, "nb_rx_queues=%d, nb_tx_queues=%d\n", nb_rx_queues, nb_tx_queues);
	internals->nb_rx_queues = nb_rx_queues;
	internals->nb_tx_queues = nb_tx_queues;
	internals->packet_size = packet_size;
	internals->numa_node = numa_node;

	/* rx and tx are so-called from point of view of first port.
	 * They are inverted from the point of view of second port
	 */
	struct rte_ring *rxtx[RTE_PMD_RING_MAX_RX_RINGS];
	char rng_name[RTE_RING_NAMESIZE];
	unsigned num_rings = RTE_MIN(RTE_PMD_RING_MAX_RX_RINGS,
			RTE_PMD_RING_MAX_TX_RINGS);

	for (i = 0; i < num_rings; i++) {
		snprintf(rng_name, sizeof(rng_name), "ETH_RXTX%u_%s", i, name);
		rxtx[i] = rte_ring_create(rng_name, 1024, numa_node,
						          RING_F_SP_ENQ|RING_F_SC_DEQ);
		if (rxtx[i] == NULL)
			return -1;
	}
	for (i = 0; i < nb_rx_queues; i++) {
		internals->rx_sonic_queues[i].rng = rxtx[i];
	}
	for (i = 0; i < nb_tx_queues; i++) {
		internals->tx_sonic_queues[i].rng = rxtx[i];
	}

	pci_dev->numa_node = numa_node;

	data->dev_private = internals;
	data->port_id = eth_dev->data->port_id;
	data->nb_rx_queues = (uint16_t)nb_rx_queues;
	data->nb_tx_queues = (uint16_t)nb_tx_queues;
	data->dev_link = pmd_link;
	data->mac_addrs = &eth_addr;
	strncpy(data->name, eth_dev->data->name, strlen(eth_dev->data->name));

	eth_dev->data = data;
	eth_dev->dev_ops = &ops;
	eth_dev->pci_dev = pci_dev;
	eth_dev->driver = &rte_sonic_pmd;

	/* finally assign rx and tx ops */
    eth_dev->rx_pkt_burst = &rx_recv_pkts;
    eth_dev->tx_pkt_burst = &tx_xmit_pkts;

    PMD_INIT_LOG(DEBUG, "Created ethdev->data at %p", internals);
	return 0;

error:
	rte_free(data);
	rte_free(pci_dev);
	rte_free(internals);

	return -1;
}

static int
rte_sonic_pmd_uninit(const char *name)
{
	struct rte_eth_dev *eth_dev = NULL;

	if (name == NULL)
		return -EINVAL;

	/* reserve an ethdev entry */
	eth_dev = rte_eth_dev_allocated(name);
	if (eth_dev == NULL)
		return -1;

	rte_free(eth_dev->data->dev_private);
	rte_free(eth_dev->data);
	rte_free(eth_dev->pci_dev);

	rte_eth_dev_release_port(eth_dev);
    return 0;
}

static struct rte_driver pmd_sonic_drv = {
	.name = "eth_sonic",
	.type = PMD_VDEV,
	.init = rte_sonic_pmd_init,
	.uninit = rte_sonic_pmd_uninit,
};

PMD_REGISTER_DRIVER(pmd_sonic_drv);
