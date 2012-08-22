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
/* functions: lipmon_init, lipmon_hook, lipmon_clean, lipmon_release */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>

#include "pna.h"
#include "pna_module.h"

MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");

int lipmon_init(void);
int lipmon_hook(struct session_key *key, int direction, struct sk_buff *skb,
                unsigned long *data);
void lipmon_clean(void);
void lipmon_release(void);

struct pna_rtmon lipmon = {
    .name = "local IP monitor",
    .init = lipmon_init,
    .hook = lipmon_hook,
    .clean = lipmon_clean,
    .release = lipmon_release,
};
PNA_MONITOR(&lipmon);

uint pna_connections = 0xffffffff;
uint pna_sessions = 0xffffffff;

PNA_PARAM(uint, pna_connections, "Number of connections to trigger alert");
PNA_PARAM(uint, pna_sessions, "Number of sessions to trigger alert");

struct lipmon_entry {
    unsigned int   local_ip;
    unsigned short connections[PNA_PROTOCOLS][PNA_DIRECTIONS];
    unsigned int   sessions[PNA_PROTOCOLS][PNA_DIRECTIONS];
    unsigned int   bytes[PNA_PROTOCOLS][PNA_DIRECTIONS];
    unsigned int   packets[PNA_PROTOCOLS][PNA_DIRECTIONS];
};
struct lipmon_entry *liptab;
#define PNA_LIPMON_BITS 17
#define PNA_LIPMON_ENTRIES (1 << PNA_LIPMON_BITS)
#define PNA_LIPMON_TABLE_SZ (PNA_LIPMON_ENTRIES*sizeof(struct lipmon_entry))

#define PNA_NEW_SESSION 0x01
#define PNA_NEW_CON  0x02

/* in-file prototypes */
static void lipmon_check(struct lipmon_entry *lip, int proto, int dir,
                         struct timeval *tv);
void lipmon_clean(void);

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
 * Local IP monitors
 */
int lipmon_init(void)
{
    /* allocate memory for liptab */
    liptab = vmalloc(PNA_LIPMON_TABLE_SZ);
    if (!liptab) {
        pna_err("insufficient memory for lipmon (%ld)", PNA_LIPMON_TABLE_SZ);
        return -ENOMEM;
    }

    /* make sure memory is clean */
    lipmon_clean();

    return 0;
}

/* insert/update entry for liptab */
static struct lipmon_entry *liptab_insert(struct session_key *key)
{
    unsigned int i;
    unsigned int hash, hash_0, hash_1;
    struct lipmon_entry *lip;
    
    hash_0 = hash_32(key->local_ip, PNA_LIPMON_BITS);
    hash_1 = pna_hash(key->local_ip, PNA_LIPMON_BITS);

    /* loop through table until we find right entry */
    for ( i = 0; i < PNA_TABLE_TRIES; i++ ) {
        /* double hashing for entry */
        hash = (hash_0 + i*hash_1) & (PNA_LIPMON_ENTRIES-1);

        /* start testing the waters */
        lip = &liptab[hash];

        /* check if IP is a match */
        if (key->local_ip == lip->local_ip) {
            return lip;
        }

        /* check if IP is clear */
        if (0 == lip->local_ip) {
            /* set up entry and return it */
            lip->local_ip = key->local_ip;
            return lip;
        }
    }
   
    return NULL;
}

static void alert(char *type, uint lip, uint amount, uint threshold,
                  struct timeval *tv)
{
    size_t len;
    char reason[MAX_STR];
#define FMT "in+out %s on all protocols for 0x%08x exceed threshold (%d > %d)"
    snprintf(reason, MAX_STR, FMT, type, lip, amount, threshold);
    len = strnlen(reason, MAX_STR);
    pna_message_signal(PNA_MSG_METH_ALERT, tv, reason, len);
#undef FMT
}

/* check a lipmon entry for threshold violations */
static void lipmon_check(struct lipmon_entry *lip, int proto, int dir,
                         struct timeval *tv)
{
    unsigned int value;

    /* check if the local ip has connected to too many hosts */
    value = lip->connections[PNA_PROTO_TCP][PNA_DIR_OUTBOUND];
    value += lip->connections[PNA_PROTO_TCP][PNA_DIR_INBOUND];
    value += lip->connections[PNA_PROTO_UDP][PNA_DIR_OUTBOUND];
    value += lip->connections[PNA_PROTO_UDP][PNA_DIR_INBOUND];
    if (value > pna_connections)
        alert("connections", lip->local_ip, value, pna_connections, tv);

    /* check if the local ip is having too many conversations */
    value = lip->sessions[PNA_PROTO_TCP][PNA_DIR_OUTBOUND];
    value += lip->sessions[PNA_PROTO_TCP][PNA_DIR_INBOUND];
    value += lip->sessions[PNA_PROTO_UDP][PNA_DIR_OUTBOUND];
    value += lip->sessions[PNA_PROTO_UDP][PNA_DIR_INBOUND];
    if (value > pna_sessions)
        alert("sessions", lip->local_ip, value, pna_sessions, tv);
}

int lipmon_hook(struct session_key *key, int direction, struct sk_buff *skb,
                unsigned long *data)
{
    struct lipmon_entry *lip;
    int *int_data = (int *)data;
    struct timeval tv;
    int protocol = protocol_map(key->l4_protocol);
   
    /* get entry */
    lip = liptab_insert(key);
    if (!lip || protocol < 0) {
        return -1;
    }

    /* get the packet arrival time */
    skb_get_timestamp(skb, &tv);

    /* if this is a new session, update sessions */
    if (*int_data & PNA_NEW_SESSION) {
        lip->sessions[protocol][direction] += 1;
    }

    /* if this is a new connection, update connections */
    if (*int_data & PNA_NEW_CON) {
        lip->connections[protocol][direction] += 1;
    }

    /* otherwise update byte/packet counts */
    lip->bytes[protocol][direction] += skb->len + ETH_OVERHEAD;
    lip->packets[protocol][direction] += 1;

    /* check for threshold violations */
    lipmon_check(lip, protocol, direction, &tv);

    return 0;
}

void lipmon_clean(void)
{
    memset(liptab, 0, PNA_LIPMON_TABLE_SZ);
}

void lipmon_release(void)
{
    vfree(liptab);
}
