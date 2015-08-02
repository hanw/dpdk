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
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>

#include <rte_log.h>
#include <rte_memory.h>

#include "sonic_poller.h"
#include "portal.h"

void poller_init(struct PortalPoller *poller, int numa_node) {

    int rc = pipe(poller->pipefd);
    if (rc != 0)
        RTE_LOG(ERR, PMD, "[%s:%d] pipe error %d:%s\n", __FUNCTION__, __LINE__, errno, strerror(errno));

    fcntl(poller->pipefd[0], F_SETFL, O_NONBLOCK);
    poller->timeout = -1; //BSIM uses 100
    poller->numa_node = numa_node;
//    poller_addFd(poller, poller->pipefd[0]);
}

/**
 * assumes holding mutex by caller.
 */
/*
void poller_addFd(struct PortalPoller *poller, int fd) {
    poller->numFds ++;
    poller->portal_fds = rte_realloc(poller->portal_fds, sizeof(struct pollfd) * poller->numFds, RTE_CACHE_LINE_SIZE);
    struct pollfd *pollfd = &poller->portal_fds[poller->numFds-1];
    pollfd->fd = fd;
    pollfd->events = POLLIN;
}

void* poller_event(struct PortalPoller *poller) {
    uint8_t ch;
    size_t rc = read(poller->pipefd[0], &ch, 1);
    if (rc < 0)
        RTE_LOG(ERR, PMD, "[%s:%d] read error %d:%s\n", __FUNCTION__, __LINE__, errno, strerror(errno));
    for (int i=0; i < numWrappers; i++) {
        if (!poller->portal_wrappers)
            RTE_LOG(ERR, PMD, "No portal_instances revent=%d\n", poller.portal_fds[i].revents);
        Portal *instance = portal_wrappers[i];
        instance->pint.item->event(&instance->pint);
        if (instance->pint.handler) {
            instance->pint.item->enabledint(&instance->pint, 1);
        }
    }
    return NULL;
}
*/

