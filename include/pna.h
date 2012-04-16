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

#ifdef __KERNEL__
# include <linux/time.h>
#endif /* __KERNEL__ */

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

/* XXX: bad practice, but it gets the job done */
/* could be trouble if Linux decides to use more netlink links */
#define NETLINK_PNA 31

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

#endif /* __PNA_H */
