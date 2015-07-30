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

typedef uint64_t	u64;
typedef uint32_t	u32;
typedef uint16_t	u16;
typedef uint8_t		u8;
typedef int64_t		s64;
typedef int32_t		s32;
typedef int16_t		s16;
typedef int8_t		s8;
typedef int		bool;

#define __le16		u16
#define __le32		u32
#define __le64      u64

#define SONIC_MAX_RING_DESC 4096

union sonic_tx_desc {
    struct {
        u64 buffer_addr;
        u32 cmd_type_len;
        u32 olinfo_status;
    } read;
};

union sonic_rx_desc {
    struct {
        __le64 pkt_addr;
        __le64 hdr_addr;
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
    volatile union sonic_tx_desc *tx_ring; /* Tx ring address */
    uint64_t               tx_ring_phys_addr;  /* Tx ring DMA address */
    struct sonic_tx_entry *sw_ring; /* virtual address of sw ring */
    uint16_t               nb_tx_desc; /* number of Tx desc */
    uint16_t               tx_head; /* index of first used tx desc */
    uint16_t               queue_id; /* tx queue index */
    uint8_t                port_id;  /* device port identifier */
    uint8_t                ctx_curr; /* current used hardware descriptor */
    uint8_t                ctx_start; /* start context position for Tx queue */

    /** ring_queue */
	struct rte_ring *rng;
	rte_atomic64_t rx_pkts;
	rte_atomic64_t tx_pkts;
	rte_atomic64_t err_pkts;
};


struct sonic_rx_entry {
    struct rte_mbuf *mbuf;    /* mbuf associated with Rx descriptor */
};

/**
 * Structure associated with each RX queue.
 */
struct sonic_rx_queue {

    struct rte_mempool *mb_pool;    /* mbuf pool to populate Rx ring */
    volatile union sonic_rx_desc *rx_ring; /* Rx ring virtual address */
    uint64_t            rx_ring_phys_addr; /* Rx ring DMA address */
    struct sonic_rx_entry *sw_ring; /* adddress of Rx software ring */
    struct rte_mbuf *pkt_first_seg; /* First segment of current packet */
    struct rte_mbuf *pkt_last_seg;  /* Last segment of current packet */
    uint16_t         nb_rx_desc;    /* number of Rx descriptors */
    uint16_t         queue_id;      /* Rx queue index */
    uint8_t          port_id;       /* Device port identifier */

    /** ring_queue */
	struct rte_ring *rng;
	rte_atomic64_t rx_pkts;
	rte_atomic64_t tx_pkts;
	rte_atomic64_t err_pkts;
};

#endif
