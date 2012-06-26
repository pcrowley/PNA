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
#else
# include <stdint.h>
#endif /* __KERNEL__ */

#define MAX_STR 1024

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
#define PNA_LOG_MAGIC0   'P'
#define PNA_LOG_MAGIC1   'N'
#define PNA_LOG_MAGIC2   'A'
#define PNA_LOG_VERSION 2
struct pna_log_header {
    unsigned char magic[3];
    unsigned char version;
    unsigned int entries;
    unsigned int start_time;
    unsigned int end_time;
};

/* PNA message commands */
#define PNA_MSG_CMD_REGISTER   0x0001
#define PNA_MSG_CMD_UNREGISTER 0x0002
#define PNA_MSG_CMD_SIGNAL     0x0003

/* PNA message signal method */
#define PNA_MSG_METH_POLL  0x0000
#define PNA_MSG_METH_ONCE  0x0001
#define PNA_MSG_METH_ALERT 0xfff0
#define PNA_MSG_METH_STOP  0xffff

#define PNA_MSG_DATA_LEN 256

struct pna_message {
    uint16_t command;
    uint16_t method;
    struct timeval timeval;
    char data[PNA_MSG_DATA_LEN];
};
#define PNA_MESSAGE_SZ (sizeof(struct pna_message))
#define PNA_MSG_NTHREADS 16

#ifndef __KERNEL__
int pna_message_init(void);
void pna_message_uninit(void);
void pna_message_send(struct pna_message *message);
struct pna_message *pna_message_recv(void);
void pna_message_reg(void);
void pna_message_unreg(void);
#endif

/* settings/structures for storing <src,dst,port> entries */

/* definition of a session for PNA */
struct session_key {
    unsigned short l3_protocol;
    unsigned char l4_protocol;
    unsigned int local_ip;
    unsigned int remote_ip;
    unsigned short local_port;
    unsigned short remote_port;
};

/* session data we're interested in off-line */
struct session_data {
    unsigned int bytes[PNA_DIRECTIONS];
    unsigned int packets[PNA_DIRECTIONS];
    unsigned int timestamp;
    unsigned int first_tstamp;
    unsigned char first_dir;
#define PNA_DATA_FLAG_CWR 0x80
#define PNA_DATA_FLAG_ECE 0x40
#define PNA_DATA_FLAG_URG 0x20
#define PNA_DATA_FLAG_ACK 0x10
#define PNA_DATA_FLAG_PSH 0x08
#define PNA_DATA_FLAG_RST 0x04
#define PNA_DATA_FLAG_SYN 0x02
#define PNA_DATA_FLAG_FIN 0x01
    unsigned char flags;
    unsigned char pad[2];
};

struct session_entry {
    struct session_key key;
    struct session_data data;
};

#endif /* __PNA_H */
