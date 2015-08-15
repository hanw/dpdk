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
#ifndef __SONIC_RXTX_H__
#define __SONIC_RXTX_H__

typedef uint64_t	u64;
typedef uint32_t	u32;
typedef uint16_t	u16;
typedef uint8_t		u8;
typedef int64_t		s64;
typedef int32_t		s32;
typedef int16_t		s16;
typedef int8_t		s8;

#define __le16		u16
#define __le32		u32
#define __le64      u64

#define SONIC_MAX_RING_DESC 4096
#define SONIC_RX_MAX_BURST 32

#define RTE_MBUF_DATA_DMA_ADDR(mb) \
	(uint64_t) ((mb)->buf_physaddr + (mb)->data_off)

#define RTE_MBUF_DATA_DMA_ADDR_DEFAULT(mb) \
	(uint64_t) ((mb)->buf_physaddr + RTE_PKTMBUF_HEADROOM)

union sonic_tx_desc {
    struct {
        u64 buffer_addr;
        u32 cmd_type_len;
        u32 olinfo_status;
    } read;
};

struct sonic_tx_entry {
    struct rte_mbuf *mbuf;    /* mbuf associated with Tx desc, if any */
    uint16_t next_id;         /* index of next descriptor in ring */
    uint16_t last_id;         /* index of last scattered descriptor */
};

/**
 * Structure associated with each TX queue.
 */
struct sonic_tx_queue {
    // Let's see if we can get tx_queue to work without a descriptor.
    struct sonic_tx_entry *sw_ring; /* virtual address of sw ring */
    uint16_t               nb_tx_desc; /* number of Tx desc */
    uint16_t               queue_id; /* tx queue index */
    uint8_t                port_id;  /* device port identifier */
    uint8_t                ctx_curr; /* current used hardware descriptor */
    uint8_t                ctx_start; /* start context position for Tx queue */
    struct rte_eth_dev    *dev; /* pointer to parent dev */
};


struct sonic_rx_entry {
    struct rte_mbuf *mbuf;    /* mbuf associated with Rx descriptor */
    __le64 dma_addr;
};

/**
 * Structure associated with each RX queue.
 */
struct sonic_rx_queue {
    struct rte_mempool    *mb_pool; /* mbuf pool to populate Rx ring */
    struct sonic_rx_entry *sw_ring; /* adddress of Rx software ring */
    uint16_t               nb_slots; /* number of Rx slots */
    uint16_t               queue_id; /* Rx queue index */
    uint16_t               port_id; /* Device port identifier */

    uint16_t               rx_nb_avail; /* nbr of staged pkts to ret to app */
    uint16_t               rx_next_avail; /* idx of next staged pkt to ret to app */
    uint16_t               rx_last_allocated; /* trigger rx buffer allocation */
    uint16_t               rx_tail; /* last received packet idx */

    uint16_t               sampling;

    struct rte_eth_dev    *dev; /* pointer to parent dev */
    struct rte_mbuf       *rx_stage[SONIC_RX_MAX_BURST * 2];
};

#endif
