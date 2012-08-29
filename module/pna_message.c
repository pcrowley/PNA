/**
 * Copyright 2011 Washington University in St Louis
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

/* netlink messages system connects to userspace listener */
/* functions: pna_message_init, pna_message_cleanup, pna_message_signal */
 
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "pna.h"
#include "pna_module.h"

/* one user process will talk with one kernel socket */
static struct sock *pna_message_sock = NULL;
static int pna_message_pid = 0;

static void pna_message_recv(struct sk_buff *skb);
static int pna_message_send(struct pna_message *message);

/* this function is called when a threshold is crossed */
int pna_message_signal(int method, struct timeval *time, char *data, uint length)
{
    struct pna_message message;

    if (length > PNA_MSG_DATA_LEN-1) {
        pna_info("pna_message: too long %d > %d\n", length, PNA_MSG_DATA_LEN-1);
        return -1;
    }

    /* this chunk prepares a message for sending */
    message.command = PNA_MSG_CMD_SIGNAL;
    message.method = method;
    memcpy(&message.timeval, time, sizeof(message.timeval));
    memcpy(&message.data, data, length);
    /* make sure we have a null terminator */
    message.data[length] = '\0';
    message.data[PNA_MSG_DATA_LEN-1] = '\0';

    return pna_message_send(&message);
}
EXPORT_SYMBOL(pna_message_signal);

/* receive a message from a user process */
static void pna_message_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct pna_message msg_out;
    struct pna_message *message;
    uint32_t *data_pid;
    struct timeval currtime;

    nlh = (struct nlmsghdr *)skb->data;
    message = (struct pna_message *)nlmsg_data(nlh);
    data_pid = (uint32_t *)message->data;

    switch (message->command) {
        case PNA_MSG_CMD_REGISTER:
            /* sanity check */
            if ( nlh->nlmsg_pid == *data_pid ) {
                /* and we know who to send messages to */
                pna_message_pid = *data_pid;
                pna_info("pna messages registered to pid %d\n", pna_message_pid);
            }
            do_gettimeofday(&currtime);
            msg_out.command = PNA_MSG_CMD_REGISTER;
            msg_out.method = PNA_MSG_METH_ONCE;
            memcpy(&msg_out.timeval, &currtime, sizeof(currtime));
            memcpy(&msg_out.data, data_pid, sizeof(*data_pid));
            pna_message_send(&msg_out);
            break;
        case PNA_MSG_CMD_UNREGISTER:
            /* sanity check */
            if ( pna_message_pid == *data_pid ) {
                /* unregister the messages */
                pna_message_pid = 0;
                pna_info("pna messages unregistered\n");
            }
            break;
        default:
            pna_warn("pna_message: invalid command %d\n", message->command);
    }
}

/* send message message to the registered user process */
static int pna_message_send(struct pna_message *message)
{
    int ret;
    struct nlmsghdr *nlh;
    struct sk_buff *skb;

    /* see if anyone has registered a user-space handler yet */
    if (pna_message_pid == 0) {
        return -1;
    }

    /* allocate the message buffer */
    skb = nlmsg_new(PNA_MESSAGE_SZ, 0);
    if (!skb) {
        pna_warn("could not allocate socket buffer\n");
        return -2;
    } 

    /* set up netlink header */
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, PNA_MESSAGE_SZ, 0);  
    NETLINK_CB(skb).dst_group = 0;

    /* copy the data to send */
    memcpy(nlmsg_data(nlh), message, PNA_MESSAGE_SZ);

    /* send the message */
    ret = nlmsg_unicast(pna_message_sock, skb, pna_message_pid);
    if (ret < 0) {
        pna_warn("could not send buffer to pid %d\n", pna_message_pid);
        return -3;
    }

    return 0;
}

int pna_message_init(void)
{
    pna_message_sock = netlink_kernel_create(&init_net, NETLINK_PNA, 0,
            pna_message_recv, NULL, THIS_MODULE);
    if (!pna_message_sock) {
        pna_err("failed to create netlink socket\n");
        return -1;
    }

    return 0;
}

void pna_message_cleanup(void)
{
    netlink_kernel_release(pna_message_sock);
}
