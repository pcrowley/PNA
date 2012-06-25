/**
 * Copyright 2012 Washington University in St Louis
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "pna.h"

/* global variables */
int socket_fd;
struct nlmsghdr *nlh = NULL;
struct msghdr nl_msg;
struct iovec nl_iov;
struct sockaddr_nl pna_user, pna_kernel; 

/*
 * netlink functions
 */
int pna_message_init(void)
{
    /* allocate space for messages */
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(PNA_MESSAGE_SZ));
    memset(nlh, 0, NLMSG_SPACE(PNA_MESSAGE_SZ));

    /* set up netlink header structure for packets */
    nlh->nlmsg_len = NLMSG_SPACE(PNA_MESSAGE_SZ);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    nl_iov.iov_base = (void *)nlh;
    nl_iov.iov_len = NLMSG_SPACE(PNA_MESSAGE_SZ);

    /* Linux can be picky about msghdrs, 0 it out */
    memset(&nl_msg, 0, sizeof(nl_msg));
    nl_msg.msg_name = (void *)&pna_kernel;
    nl_msg.msg_namelen = sizeof(pna_kernel);
    nl_msg.msg_iov = &nl_iov;
    nl_msg.msg_iovlen = 1;

    /* set up my (userspace) socket identifier */
    memset(&pna_user, 0, sizeof(pna_user));
    pna_user.nl_family = AF_NETLINK;
    pna_user.nl_pid = getpid();

    /* set up target (kernel) socket identifier */
    memset(&pna_kernel, 0, sizeof(pna_kernel));
    pna_kernel.nl_family = AF_NETLINK;
    pna_kernel.nl_pid = 0; /* i.e. Linux Kernel */
    pna_kernel.nl_groups = 0; /* unicast */

    /* open up the netlink socket */
    if ((socket_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_PNA)) < 0) {
        perror("socket");
        return -1;
    }

    /* bind ourself to the socket */
    if (bind(socket_fd, (struct sockaddr *)&pna_user, sizeof(pna_user)) < 0) {
        perror("bind");
        return -1;
    }

    return 0;
}

void pna_message_send(struct pna_message *message)
{   
    /* put data to send in packet */
    memcpy(NLMSG_DATA(nlh), message, PNA_MESSAGE_SZ);
    
    /* send the message */
    if (sendmsg(socket_fd, &nl_msg, 0) < 0) {
        perror("sendmsg");
    }
}

struct pna_message *pna_message_recv(void)
{
    if (recvmsg(socket_fd, &nl_msg, 0) < 0) {
        perror("recvmsg");
        return NULL;
    }

    /* read message from kernel */
    return (struct pna_message *)NLMSG_DATA(nlh);
}

void pna_message_reg(void)
{
    struct pna_message reg;
    uint32_t pid = getpid();

    if (socket_fd > 0) {
        /* send register message */
        reg.command = PNA_MSG_CMD_REGISTER;
        memcpy(&reg.data, &pid, sizeof(pid));
        pna_message_send(&reg);
    }
}
void pna_message_unreg(void)
{
    struct pna_message unreg;
    uint32_t pid = getpid();

    if (socket_fd > 0) {
        /* send unregister message */
        unreg.command = PNA_MSG_CMD_UNREGISTER;
        memcpy(&unreg.data, &pid, sizeof(pid));
        pna_message_send(&unreg);
    }
}

void pna_message_uninit(void)
{
    /* close the socket */
    close(socket_fd);

    /* free up space */
    free(nlh);
}
