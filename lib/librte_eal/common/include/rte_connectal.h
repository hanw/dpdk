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

#ifndef __RTE_CONNECTAL_H__
#define __RTE_CONNECTAL_H__

#include <stdint.h>

/*
 * Definitions of all functions exported by connectal.so through the generic
 * structure *connectal_ops*
 */
typedef void (*init_t)(uint32_t fd, uint64_t base, uint32_t len);
typedef void (*tx_send_pa_t)(uint64_t base, uint32_t len);
typedef void (*rx_send_pa_t)(uint64_t base, uint32_t len);
typedef void (*read_version_t)(void);
typedef void (*poll_t)(void);
typedef void (*start_default_poller_t)(void);
typedef void (*stop_default_poller_t)(void);
typedef int  (*tx_credit_available_t)(void);
typedef void (*tx_credit_decrement_t)(uint32_t v);
typedef void (*reset_rx_t)(uint32_t v);

/*
 * @internal. A structure containing the functions exposed by connectal driver.
 */
struct connectal_ops {
    init_t                      init;
    tx_send_pa_t                tx_send_pa;
    rx_send_pa_t                rx_send_pa;
    read_version_t              read_version;
    poll_t                      poll;
    start_default_poller_t      start_default_poller;
    stop_default_poller_t       stop_default_poller;
    tx_credit_available_t       tx_credit_available;
    tx_credit_decrement_t       tx_credit_decrement;
    reset_rx_t                  reset_rx;
};

int connectal_init(struct connectal_ops* ops);

extern struct connectal_ops *connectal;

#endif
