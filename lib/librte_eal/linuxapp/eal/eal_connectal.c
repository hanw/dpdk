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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <rte_common.h>
#include <rte_connectal.h>

#define LOAD_SYMBOL(N) \
        ops->N = dlsym(handle, #N); \
        if (ops->N == NULL) { \
            rte_exit(EXIT_FAILURE, "Unable to load symbol: %s\n", #N); \
        };

static const char *connectal_so = "connectal.so";
int
connectal_init(struct connectal_ops *ops)
{
    void * handle;
    handle = dlopen(connectal_so, RTLD_LAZY); //FIXME: refcnt
    if (!handle) {
        rte_exit(EXIT_FAILURE, "%s\n", dlerror());
    }

    LOAD_SYMBOL(init);
    LOAD_SYMBOL(tx_send_pa);
    LOAD_SYMBOL(rx_send_pa);
    LOAD_SYMBOL(read_version);
    LOAD_SYMBOL(poll);
    LOAD_SYMBOL(start_default_poller);
    LOAD_SYMBOL(stop_default_poller);
    LOAD_SYMBOL(tx_credit_available);
    LOAD_SYMBOL(tx_credit_decrement);

    return 0;
}

static struct connectal_ops ops = {
    .init              = NULL,
    .tx_send_pa        = NULL,
    .rx_send_pa        = NULL,
    .read_version      = NULL,
    .poll              = NULL,
    .start_default_poller = NULL,
    .stop_default_poller  = NULL,
    .tx_credit_available = NULL,
    .tx_credit_decrement = NULL,
};

struct connectal_ops *connectal = &ops;

