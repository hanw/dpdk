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

#include "sonic_rxtx.h"
#include "sonic_ethdev.h"
#include "sonic_logs.h"

static struct connectal_ops cops = {
    .dma_create        = NULL,
    .dma_free          = NULL,
    .dma_read          = NULL,
};

struct pmd_internals {
	unsigned packet_size;
	unsigned numa_node;

	unsigned nb_rx_queues;
	unsigned nb_tx_queues;

	struct sonic_rx_queue rx_sonic_queues[1];
	struct sonic_tx_queue tx_sonic_queues[1];

    struct connectal_ops *cops;
};

static struct ether_addr eth_addr = { .addr_bytes = {0} };
static const char *drivername = "SONIC PMD";
static const char *soname = "connectal.so";
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

/* bsim */
static void * so_handle;
void (*dma_create) (void);

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
connectal_init(struct connectal_ops *ops)
{
    PMD_INIT_FUNC_TRACE();
    so_handle = dlopen(soname, RTLD_LAZY);
    if (!so_handle) {
        rte_exit(EXIT_FAILURE, "Unable to find %s\n", soname);
    }

    ops->dma_create = dlsym(so_handle, "dma_create");
    PMD_INIT_FUNC_TRACE();
    if (ops->dma_create == NULL)
        goto error;

    ops->dma_free = dlsym(so_handle, "dma_free");
    PMD_INIT_FUNC_TRACE();
    if (ops->dma_free == NULL)
        goto error;

    ops->dma_read = dlsym(so_handle, "dma_read");
    PMD_INIT_FUNC_TRACE();
    if (ops->dma_read == NULL)
        goto error;

    return 0;
error:
    rte_exit(EXIT_FAILURE, "Unable to load symbol\n");
}

static int
sonic_dev_configure(struct rte_eth_dev *dev)
{
    PMD_INIT_FUNC_TRACE();
	struct pmd_internals *internals;
	if (dev == NULL)
		return;
	internals = dev->data->dev_private;

    if (internals->cops->dma_create)
        (internals->cops->dma_create)();

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
}

static void
sonic_dev_stats_reset(struct rte_eth_dev *dev)
{
    PMD_INIT_FUNC_TRACE();
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
eth_dev_sonic_create(const char *name,
		const unsigned numa_node,
		unsigned packet_size)
{
	const unsigned nb_rx_queues = 1;
	const unsigned nb_tx_queues = 1;
	struct rte_eth_dev_data *data = NULL;
	struct rte_pci_device *pci_dev = NULL;
	struct pmd_internals *internals = NULL;
	struct rte_eth_dev *eth_dev = NULL;

	if (name == NULL)
		return -EINVAL;

	RTE_LOG(INFO, PMD, "Creating sonic ethdev on numa socket %u\n",
			numa_node);

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

    /* load connectal.so */
    connectal_init(&cops);
    internals->cops = &cops;

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

	return 0;

error:
	rte_free(data);
	rte_free(pci_dev);
	rte_free(internals);

	return -1;
}

static int
rte_sonic_pmd_init(const char *name, const char *params)
{
	unsigned numa_node;
	unsigned packet_size = 64;
	int ret;

	if (name == NULL)
		return -EINVAL;

	PMD_INIT_FUNC_TRACE();

	numa_node = rte_socket_id();

    //FIXME rte_eth_driver_register, move sonic_create to driver init function
	ret = eth_dev_sonic_create(name, numa_node, packet_size);
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
