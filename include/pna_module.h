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
#ifndef __PNA_MODULE_H
#define __PNA_MODULE_H

#ifndef __KERNEL__
# error "This file is only intended for use in kernel (" __FILE__ ")"
#endif /* __KERNEL__ */

#include "pna.h"
#include <linux/if_ether.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

/* some redefs for our namespace */
#define pna_warn pr_warning
#define pna_info pr_info
#define pna_err  pr_err

/* /proc directory PNA tables will be stored in */
#define PNA_PROCDIR  "pna"
extern struct proc_dir_entry *proc_parent;

/* name format of PNA table files */
#define PNA_SESSIONFILE "session-%d"

/* a table must have at least PNA_LAG_TIME seconds before dumping */
#define PNA_LAG_TIME 2

/* frequency at which to dump the periodic session data */
#define SESSION_INTERVAL (10*MSEC_PER_SEC)

/* time interval to call real-time monitor "clean" function (milliseconds) */
#define RTMON_CLEAN_INTERVAL (10*MSEC_PER_SEC)

/* Account for Ethernet overheads (stripped by sk_buff) */
#define ETH_INTERFRAME_GAP 12   /* 9.6ms @ 1Gbps */
#define ETH_PREAMBLE       8    /* preamble + start-of-frame delimiter */
#define ETH_OVERHEAD       (ETH_INTERFRAME_GAP + ETH_PREAMBLE + ETH_HLEN + ETH_FCS_LEN)

/* allow creating parameters as input to othe kernel module */
#define PNA_PARAM(type, name, desc)              \
    module_param(name, type, S_IRUGO | S_IWUSR); \
    MODULE_PARM_DESC(name, desc)

/*
 * @init: initialization routine for a hook
 * @hook: hook function called on every packet
 * @clean: clean function called periodically to reset tables/counters
 * @release: take-down function for table data and cleanup
 * @timer: timer that defines when the clean function should fire
 */
struct pna_rtmon {
    int (*init)(void);
    int (*hook)(struct session_key *, int, struct sk_buff *, unsigned long *);
    void (*clean)(void);
    void (*release)(void);
    char *name;
    struct timer_list timer;
    struct list_head list;
};

/* create functions to handle loading/unloading of rt monitors */
#define PNA_MONITOR(monitor) \
    int __init mon_init(void) { return rtmon_load((monitor)); } \
    void mon_cleanup(void) { rtmon_unload((monitor)); } \
    module_init(mon_init); module_exit(mon_cleanup)
#define PNA_MAX_MONITORS 8

/* kernel configuration settings */
extern char *pna_iface;
extern uint pna_prefix;
extern uint pna_mask;
extern uint pna_session_entries;
extern uint pna_tables;
extern bool pna_debug;
extern bool pna_perfmon;
extern bool pna_session_mon;

/* table meta-information */
/* number of attempts to insert before giving up */
#define PNA_TABLE_TRIES 32

struct sessiontab_info {
    struct pna_hashmap *map;
    char table_name[MAX_STR];

    struct mutex read_mutex;
    int          table_dirty;
    atomic_t     smp_id;
    unsigned int nsessions;
    unsigned int nsessions_missed;
    unsigned int probes[PNA_TABLE_TRIES];
};

/* some prototypes */
unsigned int pna_hash(unsigned int key, int bits);

int session_hook(struct session_key *key, int direction, struct sk_buff *skb, int flags);
int session_init(void);
void session_cleanup(void);

int rtmon_init(void);
void rtmon_cleanup(void);
int rtmon_load(struct pna_rtmon *monitor);
void rtmon_unload(struct pna_rtmon *monitor);
int rtmon_hook(struct session_key *key, int direction, struct sk_buff *skb,
               unsigned long data);

int pna_message_init(void);
void pna_message_cleanup(void);
int pna_message_signal(int, struct timeval *, char *, uint);

#endif /* __PNA_H */
