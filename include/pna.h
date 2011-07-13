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
#ifndef __PNA_H
#define __PNA_H

/* /proc directory PNA tables will be stored in */
#define PNA_PROCDIR  "pna"

/* name format of PNA table files */
#define PNA_PROCFILE "table%d"
#define PNA_MAX_STR  16

/* a table must have at least PNA_LAG_TIME seconds before dumping */
#define PNA_LAG_TIME 2

/* time interval to call real-time monitor "clean" function (milliseconds) */
#define RTMON_CLEAN_INTERVAL (10*MSEC_PER_SEC)

/* shared kernel/user space data for alert system */
#ifndef __KERNEL__
char *pna_alert_types[] = {
    "none",
    "connections",
    "sessions",
    "ports",
    "bytes",
    "packets",
};
char *pna_alert_protocols[] = { "none", "tcp", "udp", "both", };
char *pna_alert_directions[] = { "none", "in", "out", "bi", };
#endif /* __KERNEL__ */

/* various constants */
#define PNA_DIRECTIONS 2 /* out and in */
# define PNA_DIR_OUTBOUND 0
# define PNA_DIR_INBOUND  1
#define PNA_PROTOCOLS 2 /* tcp and udp */
# define PNA_PROTO_TCP 0
# define PNA_PROTO_UDP 1

/* log file format structures */
struct pna_log_hdr {
    unsigned int start_time;
    unsigned int end_time;
    unsigned int size;
};

struct pna_log_entry {
    unsigned int local_ip;                  /* 4 */
    unsigned int remote_ip;                 /* 4 */
    unsigned short local_port;              /* 2 */
    unsigned short remote_port;             /* 2 */
    unsigned int packets[PNA_DIRECTIONS];   /* 8 */
    unsigned int bytes[PNA_DIRECTIONS];     /* 8 */
    unsigned int first_tstamp;              /* 4 */
	unsigned char l4_protocol;              /* 1 */
    unsigned char first_dir;                /* 1 */
    char pad[2];                            /* 2 */
};                                          /* = 36 */

/* XXX: bad practice, but it gets the job done */
/* could be trouble if Linux decides to use more netlink links */
#define NETLINK_PNA 31

/* PNA alert commands */
#define PNA_ALERT_CMD_REGISTER   0x0001
#define PNA_ALERT_CMD_UNREGISTER 0x0002
#define PNA_ALERT_CMD_WARN       0x0003

/* PNA alert warning reasons OR'd together: (type | proto | dir) */ 
#define PNA_ALERT_TYPE_CONNECTIONS 0x0001
#define PNA_ALERT_TYPE_SESSIONS    0x0002
#define PNA_ALERT_TYPE_PORTS       0x0003
#define PNA_ALERT_TYPE_BYTES       0x0004
#define PNA_ALERT_TYPE_PACKETS     0x0005
#define PNA_ALERT_TYPE_MASK        0x00ff
#define PNA_ALERT_TYPE_SHIFT       0

#define PNA_ALERT_PROTO_TCP        0x0100
#define PNA_ALERT_PROTO_UDP        0x0200
#define PNA_ALERT_PROTO_ALL ( PNA_ALERT_PROTO_TCP | PNA_ALERT_PROTO_UDP )
#define PNA_ALERT_PROTO_MASK       0x0f00
#define PNA_ALERT_PROTO_SHIFT      8

#define PNA_ALERT_DIR_IN           0x1000
#define PNA_ALERT_DIR_OUT          0x2000
#define PNA_ALERT_DIR_INOUT ( PNA_ALERT_DIR_IN | PNA_ALERT_DIR_OUT )
#define PNA_ALERT_DIR_MASK         0x3000
#define PNA_ALERT_DIR_SHIFT        12

struct pna_alert_msg {
    short command;
    short reason;
    unsigned int value;
    struct timeval timeval;
};
#define PNA_ALERT_MSG_SZ (sizeof(struct pna_alert_msg))

/* settings/structures for storing <src,dst,port> entries */
#define PNA_FLOW_BITS    23
#define PNA_FLOW_ENTRIES (1 << PNA_FLOW_BITS)

/* definition of a flow for PNA */
struct pna_flowkey {
    unsigned short l3_protocol;
    unsigned char l4_protocol;
    unsigned int local_ip;
    unsigned int remote_ip;
    unsigned short local_port;
    unsigned short remote_port;
};

/* flow data we're interested in off-line */
struct pna_flow_data {
    unsigned int bytes[PNA_DIRECTIONS];
    unsigned int packets[PNA_DIRECTIONS];
    unsigned int timestamp;
    unsigned int first_tstamp;
    unsigned int first_dir;
};

struct flow_entry {
    struct pna_flowkey key;
    struct pna_flow_data data;
};
#define PNA_SZ_FLOW_ENTRIES (PNA_FLOW_ENTRIES * sizeof(struct flow_entry))

#ifdef __KERNEL__

/* Account for Ethernet overheads (stripped by sk_buff) */
#include <linux/if_ether.h>
#define ETH_INTERFRAME_GAP 12   /* 9.6ms @ 1Gbps */
#define ETH_PREAMBLE       8    /* preamble + start-of-frame delimiter */
#define ETH_OVERHEAD       (ETH_INTERFRAME_GAP + ETH_PREAMBLE + ETH_HLEN + ETH_FCS_LEN)

/* kernel configuration settings */
extern char *pna_iface;
extern uint pna_prefix;
extern uint pna_mask;
extern uint pna_tables;
extern uint pna_connections;
extern uint pna_sessions;
extern uint pna_tcp_ports;
extern uint pna_tcp_bytes;
extern uint pna_tcp_packets;
extern uint pna_udp_ports;
extern uint pna_udp_bytes;
extern uint pna_udp_packets;
extern uint pna_ports;
extern uint pna_bytes;
extern uint pna_packets;
extern bool pna_debug;
extern bool pna_perfmon;
extern bool pna_flowmon;
extern bool pna_rtmon;
#endif /* __KERNEL__ */

/* table meta-information */
#ifdef __KERNEL__
/**
 * Inter-stage queue settings
 *****/
#define QUEUE_TYPE_CIRC  2
#define QUEUE_TYPE_MCBUF 3

#define QUEUE_TYPE QUEUE_TYPE_MCBUF
/*****/

struct pna_pipedata {
    struct pna_flowkey key;     /* 16 */
    int direction;              /* 4 */
    struct sk_buff *skb;        /* 8 */
    unsigned long data;         /* 8 */
} ____cacheline_aligned;
#define PNA_QUEUE_SZ (1<<14)

#define PNA_QUEUE_BATCH_SZ (PNA_QUEUE_SZ>>2)
#define PNA_QUEUE_NEXT(x) (((x) + 1) & (PNA_QUEUE_SZ - 1))

#if QUEUE_TYPE == QUEUE_TYPE_CIRC
struct pna_queue {
    int head ____cacheline_aligned;
    int tail ____cacheline_aligned;
    struct pna_pipedata data[PNA_QUEUE_SZ];
};
#elif QUEUE_TYPE == QUEUE_TYPE_MCBUF
struct pna_queue {
    /* shared control variables */
    volatile int tail ____cacheline_aligned;
    volatile int head;

    /* consumer's local variables */
    int reader_head ____cacheline_aligned;
    int reader_next;
    int reader_batch;

    /* producer's local variables */
    int writer_tail ____cacheline_aligned;
    int writer_next;
    int writer_batch;

    /* buffer data */
    struct pna_pipedata data[PNA_QUEUE_SZ];
};
#endif /* QUEUE_TYPE */

/* number of attempts to insert before giving up */
#define PNA_TABLE_TRIES 32

struct flowtab_info {
    void *table_base;
    char table_name[PNA_MAX_STR];
    struct flow_entry *flowtab;

    struct mutex read_mutex;
    time_t first_sec;
    atomic_t  smp_id;
    unsigned int nflows;
    unsigned int nflows_missed;
    unsigned int probes[PNA_TABLE_TRIES];

    struct pna_queue queue ____cacheline_aligned;
};
#endif /* __KERNEL__ */

/* some prototypes */
#ifdef __KERNEL__
unsigned int pna_hash(unsigned int key, int bits);

int flowmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb);
int flowmon_init(void);
void flowmon_cleanup(void);

int rtmon_init(void);
int rtmon_hook(struct pna_flowkey key, int direction, struct sk_buff *skb,
               unsigned long data);
void rtmon_release(void);

int conmon_init(void);
int conmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
               unsigned long *data);
void conmon_clean(void);
void conmon_release(void);

int lipmon_init(void);
int lipmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb,
               unsigned long *data);
void lipmon_clean(void);
void lipmon_release(void);

int pna_alert_warn(int reason, int value, struct timeval *time);
int pna_alert_init(void);
void pna_alert_cleanup(void);
#endif /* __KERNEL__ */

#endif /* __PNA_H */
