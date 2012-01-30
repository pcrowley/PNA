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

/* handle insertion into flow table */
/* functions: flowmon_init, flowmon_cleanup, flowmon_hook */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/percpu.h>
#include <linux/hash.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/proc_fs.h>

#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "pna_hashmap.h"
#include "pna.h"

/* kernel/user table interaction */
static int flowtab_open(struct inode *inode, struct file *filep);
static int flowtab_release(struct inode *inode, struct file *filep);
static int flowtab_mmap(struct file *filep, struct vm_area_struct *vma);
static void flowtab_clean(struct flowtab_info *info);

/* kernel functions for flow monitoring */
static struct flowtab_info *flowtab_get(struct timeval *timeval);
static int flowkey_match(struct pna_flowkey *key_a, struct pna_flowkey *key_b);
int flowmon_init(void);
void flowmon_cleanup(void);

/* pointer to information about the flow tables */
static struct flowtab_info *flowtab_info;

/* pointer to the /proc durectiry parent node */
static struct proc_dir_entry *proc_parent;

/* file operations for accessing the flowtab */
static const struct file_operations flowtab_fops = {
    .owner      = THIS_MODULE,
    .open       = flowtab_open,
    .release    = flowtab_release,
    .mmap       = flowtab_mmap,
};

/* per-cpu data */
DEFINE_PER_CPU(int, flowtab_idx);

/*
 * kernel/user table interaction
 */
/* runs when user space has opened the file */
static int flowtab_open(struct inode *inode, struct file *filep)
{
    int i;
    struct flowtab_info *info;
    struct timeval now;
    unsigned int first_sec;

    try_module_get(THIS_MODULE);

    /* find the name of file opened (index into flowtab_info) */
    sscanf(filep->f_path.dentry->d_iname, PNA_PROCFILE, &i);
    info = &flowtab_info[i];

    /* make sure the table was written and not in the last LAG_TIME */
    do_gettimeofday(&now);
    first_sec = info->first_sec + PNA_LAG_TIME;
    if (!info->table_dirty || first_sec >= now.tv_sec ) {
        module_put(THIS_MODULE);
        return -EACCES;
    }

    /* give pointer to filep struct for mmap */
    filep->private_data = info;

    /* lock the table, has the effect of kernel changing tables */
    mutex_lock(&info->read_mutex);

    return 0;
}

/* runs when user space has closed the file */
static int flowtab_release(struct inode *inode, struct file *filep)
{
    int i;
    struct flowtab_info *info;

    /* find the name of file opened (index into flowtab_info) */
    sscanf(filep->f_path.dentry->d_iname, PNA_PROCFILE, &i);
    info = &flowtab_info[i];

    /* dump a little info about that table */
    if (pna_perfmon) {
        pr_info("pna table%d_inserts:%u,table%d_drops:%u\n",
                i, info->nflows, i, info->nflows_missed);
    }

    /* clear out the table */
    hashmap_reset(info->map);

    /* this table is safe to use again */
    flowtab_clean(info);

    /* unlock this table, has the effect of being free for use again */
    mutex_unlock(&info->read_mutex);

    module_put(THIS_MODULE);
    return 0;
}

/* runs when user space wants to mmap the file */
static int flowtab_mmap(struct file *filep, struct vm_area_struct *vma)
{
    struct flowtab_info *info = filep->private_data;

    if (remap_vmalloc_range(vma, info->map->pairs, 0)) {
        pr_warning("remap_vmalloc_range failed\n");
        return -EAGAIN;
    }

    return 0;
}

/* clear out all the mflowtable data from a flowtab entry */
static void flowtab_clean(struct flowtab_info *info)
{
    info->table_dirty = 0;
    info->first_sec = 0;
    info->smp_id = 0;
    info->nflows = 0;
    info->nflows_missed = 0;
}

/* determine which flow table to use */
static struct flowtab_info *flowtab_get(struct timeval *timeval)
{
    int i;
    struct flowtab_info *info;

    /* figure out which flow table to use */
    info = &flowtab_info[get_cpu_var(flowtab_idx)];

    /* check if table is locked */
    i = 0;
    while (mutex_is_locked(&info->read_mutex) && i < pna_tables) {
        /* if it is locked try the next table ... */
        get_cpu_var(flowtab_idx) = (get_cpu_var(flowtab_idx) + 1) % pna_tables;
        put_cpu_var(flowtab_idx);
        info = &flowtab_info[get_cpu_var(flowtab_idx)];
        /* don't try a table more than once */
        i++;
    }
    if (i == pna_tables) {
        pr_warning("pna: all tables are locked\n");
        return NULL;
    }

    /* make sure this table is marked as dirty */
    // XXX: table_dirty should probably be atomic_t
    if (info->table_dirty == 0) {
        info->first_sec = timeval->tv_sec;
        info->table_dirty = 1;
        info->smp_id = smp_processor_id();
    }

    return info;
}

/* check if flow keys match */
static inline int flowkey_match(struct pna_flowkey *key_a, struct pna_flowkey *key_b)
{
    /* exploit the fact that keys are 16 bytes = 128 bits wide */
    u64 a_hi, a_lo, b_hi, b_lo;
    a_hi = *(u64 *)key_a;
    a_lo = *((u64 *)key_a+1);
    b_hi = *(u64 *)key_b;
    b_lo = *((u64 *)key_b+1);
    return (a_hi == b_hi) && (a_lo == b_lo);
}

/* Insert/Update this flow */
int flowmon_hook(struct pna_flowkey *key, int direction, struct sk_buff *skb)
{
    struct flow_entry *flow;
    struct pna_flow_data data;
    struct timeval timeval;
    struct flowtab_info *info;

    /* get the timestamp on the packet */
    skb_get_timestamp(skb, &timeval);

    if (NULL == (info = flowtab_get(&timeval))) {
        return -1;
    }

    /* now the action -- try to get the key pair */
    flow = (struct flow_entry *)hashmap_get(info->map, key);
    if (flow) {
        /* success, update packet count */
        flow->data.bytes[direction] += skb->len + ETH_OVERHEAD;
        flow->data.packets[direction] += 1;
        return 0;
    }

    /* no entry, try to put a new key pair (with data) */
    memset(&data, 0, sizeof(data));
    data.bytes[direction] = skb->len + ETH_OVERHEAD;
    data.packets[direction] = 1;
    data.first_tstamp = timeval.tv_sec;
    data.first_dir = direction;
    flow = (struct flow_entry *)hashmap_put(info->map, key, &data);
    if (flow) {
        /* successful put */
        info->nflows++;
        return 1;
    }

    /* couldn't get, couldn't put, it's a drop */
    info->nflows_missed++;
    return -1;
}

/* initialization routine for flow monitoring */
int flowmon_init(void)
{
    int i;
    struct flowtab_info *info;
    char table_str[PNA_MAX_STR];
    struct proc_dir_entry *proc_node;
    struct flow_entry e;

    /* create the /proc base dir for pna tables */
    proc_parent = proc_mkdir(PNA_PROCDIR, NULL);

    /* make memory for table meta-information */
    flowtab_info = (struct flowtab_info *)
                    vmalloc(pna_tables * sizeof(struct flowtab_info));
    if (!flowtab_info) {
        pr_err("insufficient memory for flowtab_info\n");
        flowmon_cleanup();
        return -ENOMEM;
    }
    memset(flowtab_info, 0, pna_tables * sizeof(struct flowtab_info));

    /* configure each table for use */
    for (i = 0; i < pna_tables; i++) {
        info = &flowtab_info[i];
        info->map = hashmap_create(pna_flow_entries, sizeof(e.key), sizeof(e.data));
        if (!info->map) {
            pr_err("Could not allocate hashmap (%d/%d tables, %u sessions)\n",
                    i, pna_tables, pna_flow_entries);
            flowmon_cleanup();
            return -ENOMEM;
        }
        flowtab_clean(info);

        /* initialize the read_mutec */
        mutex_init(&info->read_mutex);

        snprintf(table_str, PNA_MAX_STR, PNA_PROCFILE, i);
        strncpy(info->table_name, table_str, PNA_MAX_STR);
        proc_node = create_proc_entry(info->table_name, 0644, proc_parent);
        if (!proc_node) {
            pr_err("failed to make proc entry: %s\n", table_str);
            flowmon_cleanup();
            return -ENOMEM;
        }
        proc_node->proc_fops = &flowtab_fops;
        proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
        proc_node->uid = 0;
        proc_node->gid = 0;
        proc_node->size = PAIRS_BYTES(info->map);
    }

    /* get packet arrival timestamps */
    net_enable_timestamp();

    return 0;
}

/* clean up routine for flow monitoring */
void flowmon_cleanup(void)
{
    int i;

    net_disable_timestamp();

    /* destroy each table file we created */
    for (i = pna_tables - 1; i >= 0; i--) {
        if (flowtab_info[i].table_name[0] != '\0') {
            remove_proc_entry(flowtab_info[i].table_name, proc_parent);
        }
        if (flowtab_info[i].map != NULL) {
            hashmap_destroy(flowtab_info[i].map);
        }
    }

    /* free up table meta-information struct */
    vfree(flowtab_info);
    /* destroy /proc directory */
    remove_proc_entry(PNA_PROCDIR, NULL);
}
