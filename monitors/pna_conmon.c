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

/* some real-time monitors (connections and local ips) */
/* functions: conmon_init, conmon_hook, conmon_clean, conmon_release */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>

#include "pna.h"
#include "pna_module.h"

int conmon_init(void);
int conmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
                unsigned long *data);
void conmon_clean(void);
void conmon_release(void);

struct pna_rtmon conmon = {
    .name = "IP connection monitor",
    .init = conmon_init,
    .hook = conmon_hook,
    .clean = conmon_clean,
    .release = conmon_release,
};
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
PNA_MONITOR(&conmon);

/* monitor settings */
uint pna_tcp_ports = 0xffffffff;
uint pna_tcp_bytes = 0xffffffff;
uint pna_tcp_packets = 0xffffffff;
uint pna_udp_ports = 0xffffffff;
uint pna_udp_bytes = 0xffffffff;
uint pna_udp_packets = 0xffffffff;
uint pna_ports = 0xffffffff;
uint pna_bytes = 0xffffffff;
uint pna_packets = 0xffffffff;

PNA_PARAM(uint, pna_tcp_ports, "Number of TCP ports to trigger alert");
PNA_PARAM(uint, pna_tcp_bytes, "Number of TCP bytes to trigger alert");
PNA_PARAM(uint, pna_tcp_packets, "Number of TCP packets to trigger alert");
PNA_PARAM(uint, pna_udp_ports, "Number of UDP ports to trigger alert");
PNA_PARAM(uint, pna_udp_bytes, "Number of UDP bytes to trigger alert");
PNA_PARAM(uint, pna_udp_packets, "Number of TCP packets to trigger alert");
PNA_PARAM(uint, pna_ports, "Number of total ports to trigger alert");
PNA_PARAM(uint, pna_bytes, "Number of total bytes to trigger alert");
PNA_PARAM(uint, pna_packets, "Number of total packets to trigger alert");

struct conmon_entry {
    unsigned int   local_ip, remote_ip;
    unsigned short ports[PNA_PROTOCOLS][PNA_DIRECTIONS];
    unsigned int   bytes[PNA_PROTOCOLS][PNA_DIRECTIONS];
    unsigned int   packets[PNA_PROTOCOLS][PNA_DIRECTIONS];
    unsigned int   first_dir;
};
struct conmon_entry *contab;
#define PNA_CONMON_BITS 21
#define PNA_CONMON_ENTRIES (1 << PNA_CONMON_BITS)
#define PNA_CONMON_TABLE_SZ (PNA_CONMON_ENTRIES*sizeof(struct conmon_entry))

#define PNA_NEW_FLOW 0x01
#define PNA_NEW_CON  0x02

/* in-file prototypes */
static void conmon_check(struct conmon_entry *con, int proto, int dir,
                         struct timeval *tv);
void conmon_clean(void);

/* helper function to translate l4 protocol values to pna index */
int protocol_map(int l4_protocol)
{
    switch (l4_protocol) {
    case IPPROTO_TCP:
        return PNA_PROTO_TCP;
        break;
    case IPPROTO_UDP:
        return PNA_PROTO_UDP;
    default:
        return -1;
    };
}

/*
 * Connection monitors
 */
int conmon_init(void)
{
    /* allocate memory for contab */
    contab = vmalloc(PNA_CONMON_TABLE_SZ);
    if (!contab) {
        pr_err("insufficient memory for conmon (%ld)", PNA_CONMON_TABLE_SZ);
        return -ENOMEM;
    }

    /* make sure memory is clean */
    conmon_clean();

    return 0;
}

/* insert/update an entry in contab */
static struct conmon_entry *contab_insert(struct pna_flowkey *key)
{
    unsigned int i;
    struct conmon_entry *con;
    unsigned int hash, hash_0, hash_1;
    
    hash = key->local_ip ^ key->remote_ip;

    hash_0 = hash_32(hash, PNA_CONMON_BITS);
    hash_1 = pna_hash(hash, PNA_CONMON_BITS);

    /* loop through table until we find right entry */
    for ( i = 0; i < PNA_TABLE_TRIES; i++ ) {
        /* double hashing for entry */
        hash = (hash_0 + i*hash_1) & (PNA_CONMON_ENTRIES-1);

        /* start testing the waters */
        con = &contab[hash];

        /* check for match */
        if (key->remote_ip==con->remote_ip && key->local_ip==con->local_ip) {
            return con;
        }

        /* check for free spot */
        if (0 == con->remote_ip && 0 == con->local_ip) {
            con->remote_ip = key->remote_ip;
            con->local_ip = key->local_ip;
            return con;
        }
    }

    return NULL;
}

/* check a conmon entry for threshold violations */
static void conmon_check(struct conmon_entry *con, int proto, int dir,
                         struct timeval *tv)
{
    int reason;
    unsigned int tcp_value, udp_value;

    /* check if connection has too many tcp ports */
    tcp_value = con->ports[PNA_PROTO_TCP][PNA_DIR_OUTBOUND];
    tcp_value += con->ports[PNA_PROTO_TCP][PNA_DIR_INBOUND];
    if (tcp_value > pna_tcp_ports) {
        reason = PNA_ALERT_PROTO_TCP | PNA_ALERT_TYPE_PORTS;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }

    /* check if connection has too many tcp ports */
    udp_value = con->ports[PNA_PROTO_UDP][PNA_DIR_OUTBOUND];
    udp_value += con->ports[PNA_PROTO_UDP][PNA_DIR_INBOUND];
    if (udp_value > pna_udp_ports) {
        reason = PNA_ALERT_PROTO_UDP | PNA_ALERT_TYPE_PORTS;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }

    /* check if connection has too many tcp+udp ports */
    if (tcp_value+udp_value > pna_ports) {
        reason = PNA_ALERT_PROTO_ALL | PNA_ALERT_TYPE_PORTS;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }

    /* check if connection has too many tcp bytes */
    tcp_value = con->bytes[PNA_PROTO_TCP][PNA_DIR_OUTBOUND];
    tcp_value += con->bytes[PNA_PROTO_TCP][PNA_DIR_INBOUND];
    if (tcp_value > pna_tcp_bytes) {
        reason = PNA_ALERT_PROTO_TCP | PNA_ALERT_TYPE_BYTES;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }

    /* check if connection has too many udp bytes */
    udp_value = con->bytes[PNA_PROTO_UDP][PNA_DIR_OUTBOUND];
    udp_value += con->bytes[PNA_PROTO_UDP][PNA_DIR_INBOUND];
    if (udp_value > pna_udp_bytes) {
        reason = PNA_ALERT_PROTO_UDP | PNA_ALERT_TYPE_BYTES;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }

    /* check if connection has too many tcp+udp bytes */
    if (tcp_value+udp_value > pna_bytes) {
        reason = PNA_ALERT_PROTO_ALL | PNA_ALERT_TYPE_BYTES;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }

    /* check if connection has too many tcp packets */
    tcp_value = con->packets[PNA_PROTO_TCP][PNA_DIR_OUTBOUND];
    tcp_value += con->packets[PNA_PROTO_TCP][PNA_DIR_INBOUND];
    if (tcp_value > pna_tcp_packets) {
        reason = PNA_ALERT_PROTO_TCP | PNA_ALERT_TYPE_PACKETS;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }

    /* check if connection has too many udp packets */
    udp_value = con->packets[PNA_PROTO_UDP][PNA_DIR_OUTBOUND];
    udp_value += con->packets[PNA_PROTO_UDP][PNA_DIR_INBOUND];
    if (udp_value > pna_udp_packets) {
        reason = PNA_ALERT_PROTO_UDP | PNA_ALERT_TYPE_PACKETS;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }

    /* check if connection has too many tcp+udp packets */
    if (tcp_value+udp_value > pna_packets) {
        reason = PNA_ALERT_PROTO_ALL | PNA_ALERT_TYPE_PACKETS;
        reason |= PNA_ALERT_DIR_INOUT;
        pna_alert_warn(reason, con->local_ip, tv);
    }
}

int conmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
                unsigned long *data)
{
    struct conmon_entry *con;
    int *int_data = (int *)data;
    int protocol = protocol_map(key->l4_protocol);
    struct timeval tv;

    /* get entry */
    con = contab_insert(key);
    if (!con || protocol < 0) {
        return -1;
    }

    /* get the packet arrival time */
    skb_get_timestamp(skb, &tv);

    /* if this is a new flow, update the port counts */
    if (*int_data & PNA_NEW_FLOW) {
        con->ports[protocol][direction] += 1;
    }

    /* update bytes and packets for this entry no matter what */
    con->bytes[protocol][direction] += skb->len + ETH_OVERHEAD;
    con->packets[protocol][direction] += 1;

    /* if this is a new entry also put in first_dir and add ports */
    if ( 0 == con->first_dir ) {
        con->first_dir = (1 << direction);
        /* pass along that this is a new entry */
        *int_data |= PNA_NEW_CON;
    }

    /* check for threshold violations */
    conmon_check(con, protocol, direction, &tv);

    return 0;
}

void conmon_clean(void)
{
    memset(contab, 0, PNA_CONMON_TABLE_SZ);
}

void conmon_release(void)
{
    vfree(contab);
}

