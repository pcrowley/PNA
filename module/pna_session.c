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

/* handle insertion into session table */
/* functions: session_init, session_cleanup, session_hook */

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

#include "pna.h"
#include "pna_module.h"
#include "pna_hashmap.h"

/* kernel/user table interaction */
static int sessiontab_open(struct inode *inode, struct file *filep);
static int sessiontab_release(struct inode *inode, struct file *filep);
static int sessiontab_mmap(struct file *filep, struct vm_area_struct *vma);
static void sessiontab_clean(struct sessiontab_info *info);

/* kernel functions for session monitoring */
static struct sessiontab_info *sessiontab_get(struct timeval *timeval);
static int sessionkey_match(struct session_key *a, struct session_key *b);
int session_init(void);
void session_cleanup(void);

/* pointer to information about the session tables */
static struct sessiontab_info *sessiontab_info;

/* pointer to the /proc durectiry parent node */
static struct proc_dir_entry *proc_parent;

/* file operations for accessing the sessiontab */
static const struct file_operations sessiontab_fops = {
    .owner      = THIS_MODULE,
    .open       = sessiontab_open,
    .release    = sessiontab_release,
    .mmap       = sessiontab_mmap,
};

/* per-cpu data */
DEFINE_PER_CPU(int, sessiontab_idx);

/*
 * kernel/user table interaction
 */
/* runs when user space has opened the file */
static int sessiontab_open(struct inode *inode, struct file *filep)
{
    int i;
    struct sessiontab_info *info;
    struct timeval now;
    unsigned int first_sec;

    try_module_get(THIS_MODULE);

    /* find the name of file opened (index into sessiontab_info) */
    sscanf(filep->f_path.dentry->d_iname, PNA_PROCFILE, &i);
    info = &sessiontab_info[i];

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
static int sessiontab_release(struct inode *inode, struct file *filep)
{
    int i;
    struct sessiontab_info *info;

    /* find the name of file opened (index into sessiontab_info) */
    sscanf(filep->f_path.dentry->d_iname, PNA_PROCFILE, &i);
    info = &sessiontab_info[i];

    /* dump a little info about that table */
    if (pna_perfmon) {
        pr_info("pna table%d_inserts:%u,table%d_drops:%u\n",
                i, info->nsessions, i, info->nsessions_missed);
    }

    /* clear out the table */
    hashmap_reset(info->map);

    /* this table is safe to use again */
    sessiontab_clean(info);

    /* unlock this table, has the effect of being free for use again */
    mutex_unlock(&info->read_mutex);

    module_put(THIS_MODULE);
    return 0;
}

/* runs when user space wants to mmap the file */
static int sessiontab_mmap(struct file *filep, struct vm_area_struct *vma)
{
    struct sessiontab_info *info = filep->private_data;

    if (remap_vmalloc_range(vma, info->map->pairs, 0)) {
        pr_warning("remap_vmalloc_range failed\n");
        return -EAGAIN;
    }

    return 0;
}

/* clear out all the msessiontable data from a sessiontab entry */
static void sessiontab_clean(struct sessiontab_info *info)
{
    info->table_dirty = 0;
    info->first_sec = 0;
    info->smp_id = 0;
    info->nsessions = 0;
    info->nsessions_missed = 0;
}

/* determine which session table to use */
static struct sessiontab_info *sessiontab_get(struct timeval *timeval)
{
    int i;
    struct sessiontab_info *info;

    /* figure out which session table to use */
    info = &sessiontab_info[get_cpu_var(sessiontab_idx)];

    /* check if table is locked */
    i = 0;
    while (mutex_is_locked(&info->read_mutex) && i < pna_tables) {
        /* if it is locked try the next table ... */
        get_cpu_var(sessiontab_idx) = (get_cpu_var(sessiontab_idx) + 1) % pna_tables;
        put_cpu_var(sessiontab_idx);
        info = &sessiontab_info[get_cpu_var(sessiontab_idx)];
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

/* check if session keys match */
static inline int sessionkey_match(struct session_key *a, struct session_key *b)
{
    /* exploit the fact that keys are 16 bytes = 128 bits wide */
    u64 a_hi, a_lo, b_hi, b_lo;
    a_hi = *(u64 *)a;
    a_lo = *((u64 *)a+1);
    b_hi = *(u64 *)b;
    b_lo = *((u64 *)b+1);
    return (a_hi == b_hi) && (a_lo == b_lo);
}

/* Insert/Update this session */
int session_hook(struct session_key *key, int direction, struct sk_buff *skb)
{
    struct session_entry *session;
    struct session_data data;
    struct timeval timeval;
    struct sessiontab_info *info;

    /* get the timestamp on the packet */
    skb_get_timestamp(skb, &timeval);

    if (NULL == (info = sessiontab_get(&timeval))) {
        return -1;
    }

    /* now the action -- try to get the key pair */
    session = (struct session_entry *)hashmap_get(info->map, key);
    if (session) {
        /* success, update packet count */
        session->data.bytes[direction] += skb->len + ETH_OVERHEAD;
        session->data.packets[direction] += 1;
        return 0;
    }

    /* no entry, try to put a new key pair (with data) */
    memset(&data, 0, sizeof(data));
    data.bytes[direction] = skb->len + ETH_OVERHEAD;
    data.packets[direction] = 1;
    data.first_tstamp = timeval.tv_sec;
    data.first_dir = direction;
    session = (struct session_entry *)hashmap_put(info->map, key, &data);
    if (session) {
        /* successful put */
        info->nsessions++;
        return 1;
    }

    /* couldn't get, couldn't put, it's a drop */
    info->nsessions_missed++;
    return -1;
}

/* initialization routine for session monitoring */
int session_init(void)
{
    int i;
    struct sessiontab_info *info;
    char table_str[PNA_MAX_STR];
    struct proc_dir_entry *proc_node;
    struct session_entry e;

    /* create the /proc base dir for pna tables */
    proc_parent = proc_mkdir(PNA_PROCDIR, NULL);

    /* make memory for table meta-information */
    sessiontab_info = (struct sessiontab_info *)
                    vmalloc(pna_tables * sizeof(struct sessiontab_info));
    if (!sessiontab_info) {
        pr_err("insufficient memory for sessiontab_info\n");
        session_cleanup();
        return -ENOMEM;
    }
    memset(sessiontab_info, 0, pna_tables * sizeof(struct sessiontab_info));

    /* configure each table for use */
    for (i = 0; i < pna_tables; i++) {
        info = &sessiontab_info[i];
        info->map = hashmap_create(pna_session_entries, sizeof(e.key), sizeof(e.data));
        if (!info->map) {
            pr_err("Could not allocate hashmap (%d/%d tables, %u sessions)\n",
                    i, pna_tables, pna_session_entries);
            session_cleanup();
            return -ENOMEM;
        }
        sessiontab_clean(info);

        /* initialize the read_mutec */
        mutex_init(&info->read_mutex);

        snprintf(table_str, PNA_MAX_STR, PNA_PROCFILE, i);
        strncpy(info->table_name, table_str, PNA_MAX_STR);
        proc_node = create_proc_entry(info->table_name, 0644, proc_parent);
        if (!proc_node) {
            pr_err("failed to make proc entry: %s\n", table_str);
            session_cleanup();
            return -ENOMEM;
        }
        proc_node->proc_fops = &sessiontab_fops;
        proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
        proc_node->uid = 0;
        proc_node->gid = 0;
        proc_node->size = PAIRS_BYTES(info->map);
    }

    /* get packet arrival timestamps */
    net_enable_timestamp();

    return 0;
}

/* clean up routine for session monitoring */
void session_cleanup(void)
{
    int i;

    net_disable_timestamp();

    /* destroy each table file we created */
    for (i = pna_tables - 1; i >= 0; i--) {
        if (sessiontab_info[i].table_name[0] != '\0') {
            remove_proc_entry(sessiontab_info[i].table_name, proc_parent);
        }
        if (sessiontab_info[i].map != NULL) {
            hashmap_destroy(sessiontab_info[i].map);
        }
    }

    /* free up table meta-information struct */
    vfree(sessiontab_info);
    /* destroy /proc directory */
    remove_proc_entry(PNA_PROCDIR, NULL);
}
