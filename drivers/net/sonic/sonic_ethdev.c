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


#include "sonic_ethdev.h"
#include "sonic_logs.h"

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

static int eth_sonic_dev_init(struct rte_eth_dev *eth_dev);
static int  sonic_dev_configure(struct rte_eth_dev *dev);
static int  sonic_dev_start(struct rte_eth_dev *dev);
static void sonic_dev_stop(struct rte_eth_dev *dev);
static void sonic_dev_close(struct rte_eth_dev *dev);
static void sonic_dev_stats_get(struct rte_eth_dev *dev,
				struct rte_eth_stats *stats);
static void sonic_dev_stats_reset(struct rte_eth_dev *dev);
static void sonic_dev_info_get(struct rte_eth_dev *dev,
			       struct rte_eth_dev_info *dev_info);
static int sonic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);

static void sonic_dev_link_status_print(struct rte_eth_dev *dev);
static int sonic_dev_lsc_interrupt_setup(struct rte_eth_dev *dev);
static int sonic_dev_interrupt_get_status(struct rte_eth_dev *dev);
static int sonic_dev_interrupt_action(struct rte_eth_dev *dev);
static void sonic_dev_interrupt_handler(struct rte_intr_handle *handle,
		void *param);
static void sonic_dev_interrupt_delayed_handler(void *param);
static void sonic_add_rar(struct rte_eth_dev *dev, struct ether_addr *mac_addr,
		uint32_t index, uint32_t pool);
static void sonic_remove_rar(struct rte_eth_dev *dev, uint32_t index);

static int sonic_dev_set_mc_addr_list(struct rte_eth_dev *dev,
				      struct ether_addr *mc_addr_set,
				      uint32_t nb_mc_addr);
static int sonic_dev_link_update(struct rte_eth_dev *dev __rte_unused,
            int wait_to_complete __rte_unused);

static const struct eth_dev_ops ops = {
	.dev_configure        = sonic_dev_configure,
	.dev_start            = sonic_dev_start,
	.dev_stop             = sonic_dev_stop,
	.dev_set_link_up    = NULL,
	.dev_set_link_down  = NULL,
	.dev_close            = sonic_dev_close,
	.promiscuous_enable   = NULL,
	.promiscuous_disable  = NULL,
	.allmulticast_enable  = NULL,
	.allmulticast_disable = NULL,
	.link_update          = sonic_dev_link_update,
	.stats_get            = sonic_dev_stats_get,
	.stats_reset          = sonic_dev_stats_reset,
	.queue_stats_mapping_set = NULL,
	.dev_infos_get        = sonic_dev_info_get,
	.mtu_set              = sonic_dev_mtu_set,
	.vlan_filter_set      = NULL,
	.vlan_tpid_set        = NULL,
	.vlan_offload_set     = NULL,
	.vlan_strip_queue_set = NULL,
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
	.dev_led_on           = NULL,
	.dev_led_off          = NULL,
	.flow_ctrl_get        = NULL,
	.flow_ctrl_set        = NULL,
	.priority_flow_ctrl_set = NULL,
	.mac_addr_add         = sonic_add_rar,
	.mac_addr_remove      = sonic_remove_rar,
	.uc_hash_table_set    = NULL,
	.uc_all_hash_table_set  = NULL,
	.mirror_rule_set      = NULL,
	.mirror_rule_reset    = NULL,
	.set_vf_rx_mode       = NULL,
	.set_vf_rx            = NULL,
	.set_vf_tx            = NULL,
	.set_vf_vlan_filter   = NULL,
	.set_queue_rate_limit = NULL,
	.set_vf_rate_limit    = NULL,
	.reta_update          = NULL,
	.reta_query           = NULL,
#ifdef RTE_NIC_BYPASS
	.bypass_init          = NULL,
	.bypass_state_set     = NULL,
	.bypass_state_show    = NULL,
	.bypass_event_set     = NULL,
	.bypass_event_show    = NULL,
	.bypass_wd_timeout_set  = NULL,
	.bypass_wd_timeout_show = NULL,
	.bypass_ver_show      = NULL,
	.bypass_wd_reset      = NULL,
#endif /* RTE_NIC_BYPASS */
	.rss_hash_update      = NULL,
	.rss_hash_conf_get    = NULL,
	.filter_ctrl          = NULL,
	.set_mc_addr_list     = NULL,
	.timesync_enable      = NULL,
	.timesync_disable     = NULL,
	.timesync_read_rx_timestamp = NULL,
	.timesync_read_tx_timestamp = NULL,
};


/*
 * This function is based on code in sonic_attach() in base/sonic.c.
 * It returns 0 on success.
 */
static int
eth_sonic_dev_init(struct rte_eth_dev *eth_dev)
{
    PMD_INIT_FUNC_TRACE();
    return 0;
}

static int
sonic_dev_configure(struct rte_eth_dev *dev)
{
    PMD_INIT_FUNC_TRACE();
    return 0;
}

/*
 * Configure device link speed and setup link.
 * It returns 0 on success.
 */
static int
sonic_dev_start(struct rte_eth_dev *dev)
{
    PMD_INIT_FUNC_TRACE();
	if (dev == NULL)
		return -EINVAL;

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
	unsigned i, num_stats;
	unsigned long rx_total = 0, tx_total = 0, tx_err_total = 0;
	const struct pmd_internals *internal;

	if ((dev == NULL) || (stats == NULL))
		return;

	internal = dev->data->dev_private;
	num_stats = RTE_MIN((unsigned)RTE_ETHDEV_QUEUE_STAT_CNTRS,
			RTE_MIN(internal->nb_rx_queues,
				RTE_DIM(internal->rx_sonic_queues)));
	for (i = 0; i < num_stats; i++) {
		stats->q_ipackets[i] =
			internal->rx_sonic_queues[i].rx_pkts.cnt;
		rx_total += stats->q_ipackets[i];
	}

	num_stats = RTE_MIN((unsigned)RTE_ETHDEV_QUEUE_STAT_CNTRS,
			RTE_MIN(internal->nb_tx_queues,
				RTE_DIM(internal->tx_sonic_queues)));
	for (i = 0; i < num_stats; i++) {
		stats->q_opackets[i] =
			internal->tx_sonic_queues[i].tx_pkts.cnt;
		stats->q_errors[i] =
			internal->tx_sonic_queues[i].err_pkts.cnt;
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
	struct pmd_internals *internal;

	if (dev == NULL)
		return;

	internal = dev->data->dev_private;
	for (i = 0; i < RTE_DIM(internal->rx_sonic_queues); i++)
		internal->rx_sonic_queues[i].rx_pkts.cnt = 0;
	for (i = 0; i < RTE_DIM(internal->tx_sonic_queues); i++) {
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
sonic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
    PMD_INIT_FUNC_TRACE();
    return 0;
}

static void
sonic_add_rar(struct rte_eth_dev *dev, struct ether_addr *mac_addr,
				uint32_t index, uint32_t pool)
{
    PMD_INIT_FUNC_TRACE();
}

static void
sonic_remove_rar(struct rte_eth_dev *dev, uint32_t index)
{
    PMD_INIT_FUNC_TRACE();
}

static inline uint16_t
rx_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	     uint16_t nb_pkts)
{
	int i;
	struct sonic_queue *h = rx_queue;
	unsigned packet_size;

	if ((rx_queue == NULL) || (rx_pkts == NULL))
		return 0;

	packet_size = h->internals->packet_size;
	for (i = 0; i < nb_pkts; i++) {
		rx_pkts[i] = rte_pktmbuf_alloc(h->mb_pool);
        //printf("rx_pkts[%d], virtaddr=%p, phyaddr=%lx\n", i, rx_pkts[i]->buf_addr, rx_pkts[i]->buf_physaddr);
		if (!rx_pkts[i])
			break;
		rx_pkts[i]->data_len = (uint16_t)packet_size;
		rx_pkts[i]->pkt_len = packet_size;
		rx_pkts[i]->nb_segs = 1;
		rx_pkts[i]->next = NULL;
	}

	rte_atomic64_add(&(h->rx_pkts), i);

	return i;
}

static inline uint16_t
tx_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	     uint16_t nb_pkts)
{
	int i;
	struct sonic_queue *h = tx_queue;

	if ((tx_queue == NULL) || (tx_pkts == NULL))
		return 0;

	for (i = 0; i < nb_pkts; i++)
		rte_pktmbuf_free(tx_pkts[i]);

	rte_atomic64_add(&(h->tx_pkts), i);

	return i;
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
rte_pmd_sonic_devinit(const char *name, const char *params)
{
	unsigned numa_node;
	unsigned packet_size = 64;
	int ret;

	if (name == NULL)
		return -EINVAL;

	PMD_INIT_FUNC_TRACE();

	numa_node = rte_socket_id();

	ret = eth_dev_sonic_create(name, numa_node, packet_size);
}

static int
rte_pmd_sonic_devuninit(const char *name)
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
	.init = rte_pmd_sonic_devinit,
	.uninit = rte_pmd_sonic_devuninit,
};

PMD_REGISTER_DRIVER(pmd_sonic_drv);
