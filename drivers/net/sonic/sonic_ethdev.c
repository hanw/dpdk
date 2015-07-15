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

#include "sonic_ethdev.h"

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

static const struct eth_dev_ops sonic_eth_dev_ops = {
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
	.link_update          = NULL,
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
   // stub
   return 0;
}

static int
sonic_dev_configure(struct rte_eth_dev *dev)
{
   // stub
}


/*
 * Configure device link speed and setup link.
 * It returns 0 on success.
 */
static int
sonic_dev_start(struct rte_eth_dev *dev)
{
   // stub
   return 0;
}

/*
 * Stop device: disable rx and tx functions to allow for reconfiguring.
 */
static void
sonic_dev_stop(struct rte_eth_dev *dev)
{
   // stub
}

/*
 * Reest and stop device.
 */
static void
sonic_dev_close(struct rte_eth_dev *dev)
{
   // stub
}

/*
 * This function is based on sonic_update_stats_counters() in base/sonic.c
 */
static void
sonic_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
   // stub
}

static void
sonic_dev_stats_reset(struct rte_eth_dev *dev)
{
   // stub
}

static void
sonic_dev_info_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
   // stub
}

static int
sonic_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
   // stub
   return 0;
}

static void
sonic_add_rar(struct rte_eth_dev *dev, struct ether_addr *mac_addr,
				uint32_t index, uint32_t pool)
{
   // stub
}

static void
sonic_remove_rar(struct rte_eth_dev *dev, uint32_t index)
{
   // stub
}

