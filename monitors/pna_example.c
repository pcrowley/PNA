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

/**
 * Example PNA monitor.
 * This example is simple so it doesn't use the .init() or .release()
 * callbacks.  It does create a variable called "sample_freq" which should be
 * available under /sys/module/pna/parameters/sample_freq.
 * 
 * All the monitor does is print out some information for 1 out of every
 * sample_freq packets.
 */
/* functions: example_hook, example_clean */
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>

#include "pna.h"
#include "pna_module.h"

static int example_init(void);
static void example_release(void);
static int example_hook(struct session_key *, int, struct sk_buff *, unsigned long *);
static void example_clean(void);

struct pna_rtmon example = {
    .name = "Example monitor",
    .init = example_init,       /**< allocate resource on load */
    .hook = example_hook,       /**< called for every packet PNA sees */
    .clean = example_clean,     /**< periodic maintenance callback */
    .release = example_release, /**< release resource on unload */
};
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
PNA_MONITOR(&example);

uint sample_freq = 100;
PNA_PARAM(uint, sample_freq, "Frequency at which to print out packets");

/**
 * Procfile handlers
 */
/* file operations for accessing the sessiontab */
ssize_t example_pread(struct file *, char __user *, size_t, loff_t *);

#define PROC_NAME "example"
int path_len;
char path[MAX_STR];
static const struct file_operations example_fops = {
    .owner   = THIS_MODULE,
    .read    = example_pread,
};

// we'll keep it simple and just use a single buffer
#define MAX_PKT_LEN 2048
char pkt_data[MAX_PKT_LEN];
size_t full = 0;
wait_queue_head_t pkt_queue;

ssize_t example_pread(struct file *filep,
                     char __user *buf, size_t len, loff_t *ppos)
{
    /* wait until something is ready */
    if (!full) {
        wait_event_interruptible(pkt_queue, (0 != full) );
    }

    /* only copy our data if user buf is too long */
    if (len >= full) {
        len = full;
    }

    /* do the copy */
    memcpy(buf, &pkt_data[*ppos], len);
    full -= len;
    return len;
}

/**
 * PNA example monitor hook
 */
static int example_hook(struct session_key *key, int direction,
                        struct sk_buff *skb, unsigned long *data)
{
    static int index = 0;
    struct pna_packet *pkt;

    if (index++ == sample_freq) {
        index = 0;
        if (!full) {
            full = skb->len + ETH_HLEN + sizeof(*pkt);
            if (full > MAX_PKT_LEN) {
                full = MAX_PKT_LEN;
            }
            /* copy packet into local buffer */
            pkt = (struct pna_packet *)&pkt_data[0];
            pkt->ts = ktime_to_timeval(skb->tstamp);
            pkt->pkt_len = skb->len + ETH_HLEN;
            pkt->data_len = full;
            memcpy(pkt->data, skb_mac_header(skb), full - sizeof(*pkt));

            /* wake up the queue */
            wake_up_interruptible(&pkt_queue);
        }
    }

    return 0;
}

static void example_clean(void)
{
    pna_info("pna_example: periodic callback\n");
}

/**
 * Construct the full path to a procfile entry.
 */
static int proc_path(char *buf, ssize_t len, struct proc_dir_entry *entry)
{
    int off = 0;

    if (entry->parent != NULL && entry != entry->parent) {
        off = proc_path(buf, len, entry->parent);
        buf += off;
        len -= off;
    }
    strncpy(buf, entry->name, len);
    strncpy(buf + entry->namelen, "/", 1);

    return off + entry->namelen + 1;
}

static int example_init(void)
{
    struct proc_dir_entry *proc_node;
    struct timeval tv;

    /* initilize packet queue */
    init_waitqueue_head(&pkt_queue);

    /* create procfile */
    proc_node = create_proc_entry(PROC_NAME, 0644, proc_parent);
    if (!proc_node) {
        pna_err("could not create proc entry %s\n", PROC_NAME);
        return -ENOMEM;
    }
    proc_node->proc_fops = &example_fops;
    proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
    proc_node->uid = 0;
    proc_node->gid = 0;
    proc_node->size = MAX_PKT_LEN;

    /* signal userspace to start polling procfile */
    path_len = proc_path(path, MAX_STR, proc_node);
    path[path_len-1] = '\0';
    do_gettimeofday(&tv);
    pna_message_signal(PNA_MSG_METH_POLL, &tv, path, path_len);

    return 0;
}

static void example_release(void)
{
    struct timeval tv;

    /* signal userspace to stop polling procfile */
    do_gettimeofday(&tv);
    pna_message_signal(PNA_MSG_METH_STOP, &tv, path, path_len);

    /* destroy procfile */
    remove_proc_entry(PROC_NAME, proc_parent);
}
