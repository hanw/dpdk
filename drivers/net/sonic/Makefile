# Copyright (c) 2015 Cornell University
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#

include $(RTE_SDK)/mk/rte.vars.mk

ifndef SONIC_INCLUDE
    $(error SONIC_INCLUDE is undefined, should point to generated /jni directory)
endif
ifndef CONNECTAL_INCLUDE
    $(error CONNECTAL_INCLUDE is undefined, should point to <CONNECTAL>/cpp directory)
endif

#
# library name
#
LIB = librte_pmd_sonic.a

CFLAGS += -O3
CFLAGS += -I $(CONNECTAL_INCLUDE)
CFLAGS += -I $(SONIC_INCLUDE)
#CFLAGS += $(WERROR_FLAGS)

EXPORT_MAP := rte_pmd_sonic_version.map

LIBABIVER := 1

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_SONIC_PMD) += sonic_rxtx.c
SRCS-$(CONFIG_RTE_LIBRTE_SONIC_PMD) += sonic_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_SONIC_PMD) += sonic_poller.c

# this lib depends upon:
DEPDIRS-$(CONFIG_RTE_LIBRTE_SONIC_PMD) += lib/librte_eal lib/librte_ether
DEPDIRS-$(CONFIG_RTE_LIBRTE_SONIC_PMD) += lib/librte_mempool lib/librte_mbuf
DEPDIRS-$(CONFIG_RTE_LIBRTE_SONIC_PMD) += lib/librte_net lib/librte_malloc

include $(RTE_SDK)/mk/rte.lib.mk
