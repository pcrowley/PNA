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

/* netlink alerts system connects to userspace listener */
/* functions: pna_alert_init, pna_alert_cleanup, pna_alert_warn */
 
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "pna.h"

/* one user process will talk with one kernel socket */
static struct sock *pna_alert_sock = NULL;
static int pna_alert_pid = 0;

static void pna_alert_recv(struct sk_buff *skb);
static int pna_alert_send(struct pna_alert_msg *alert);

/* this function is called when a threshold is crossed */
int pna_alert_warn(int reason, int value, struct timeval *time)
{
    struct pna_alert_msg alert;

    /* this chunk prepares a message for sending */
    alert.command = PNA_ALERT_CMD_WARN;
    alert.reason = reason;
    alert.value = value;
    memcpy(&alert.timeval, time, sizeof(alert.timeval));

    return pna_alert_send(&alert);
}

/* receive a message from a user process */
static void pna_alert_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct pna_alert_msg *alert;

    nlh = (struct nlmsghdr *)skb->data;
    alert = (struct pna_alert_msg *)nlmsg_data(nlh);

    switch (alert->command) {
        case PNA_ALERT_CMD_REGISTER:
            /* sanity check */
            if ( nlh->nlmsg_pid == alert->value ) {
                /* and we know who to send messages to */
                pna_alert_pid = alert->value;
                printk(KERN_INFO "pna alerts registered to pid %d\n", pna_alert_pid);
            }
            break;
        case PNA_ALERT_CMD_UNREGISTER:
            /* sanity check */
            if ( pna_alert_pid == alert->value ) {
                /* unregister the alerts */
                pna_alert_pid = 0;
                printk(KERN_INFO "pna alerts unregistered\n");
            }
            break;
        default:
            printk(KERN_WARNING "pna_alert: invalid command %d\n", alert->command);
    }
}

/* send alert message to the registered user process */
static int pna_alert_send(struct pna_alert_msg *alert)
{
    int ret;
    struct nlmsghdr *nlh;
    struct sk_buff *skb;

    /* see if anyone has registered a user-space handler yet */
    if (pna_alert_pid == 0) {
        return -1;
    }

    /* allocate the message buffer */
    skb = nlmsg_new(PNA_ALERT_MSG_SZ, 0);
    if (!skb) {
        printk(KERN_WARNING "could not allocate socket buffer\n");
        return -2;
    } 

    /* set up netlink header */
    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, PNA_ALERT_MSG_SZ, 0);  
    NETLINK_CB(skb).dst_group = 0;

    /* copy the data to send */
    memcpy(nlmsg_data(nlh), alert, PNA_ALERT_MSG_SZ);

    /* send the message */
    ret = nlmsg_unicast(pna_alert_sock, skb, pna_alert_pid);
    if (ret < 0) {
        printk(KERN_WARNING "could not send buffer to pid %d\n", pna_alert_pid);
        return -3;
    }

    return 0;
}

int pna_alert_init(void)
{
    pna_alert_sock = netlink_kernel_create(&init_net, NETLINK_PNA, 0,
            pna_alert_recv, NULL, THIS_MODULE);
    if (!pna_alert_sock) {
        printk(KERN_ERR "failed to create netlink socket\n");
        return -1;
    }

    return 0;
}

void pna_alert_cleanup(void)
{
    netlink_kernel_release(pna_alert_sock);
}
