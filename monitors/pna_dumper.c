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
 * Generic "dumper" module. No filters by default, but can be
 * loaded/associated with a named file for dumping matching packets.
 *
 * Once loaded:
 *   echo "<name> <expr>" > /sys/module/pna/parameters/add
 * will install a new packet filter <expr> and write to /proc/pna/<name>
 *
 * Likewise:
 *   echo "<name>" > /sys/module/pna/parameters/remove
 * will delete a packet filter.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/skbuff.h>
#include <linux/hash.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/filter.h>
#include <linux/tcp.h>

#include "pna.h"
#include "pna_module.h"

static int dumper_init(void);
static void dumper_release(void);
static int dumper_hook(struct session_key *, int, struct sk_buff *, unsigned long *);
//static void dumper_clean(void);

struct pna_rtmon dumper = {
    .name = "Packet Dumper",
    .init = dumper_init,       /**< allocate resource on load */
    .hook = dumper_hook,       /**< called for every packet PNA sees */
    //.clean = dumper_clean,     /**< periodic maintenance callback */
    .release = dumper_release, /**< release resource on unload */
};
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
PNA_MONITOR(&dumper);

/**
 * Per expression dumper structure
 */
#define MAX_PKT_LEN 2048
struct dumper {
    struct list_head   list;
    wait_queue_head_t  queue;
    char               name[MAX_STR];
    char               path[MAX_STR];
    ssize_t            path_len;
    struct sock_filter *filter;
    int                filter_len;
    size_t             buffer_len;
    loff_t             buffer_pos;
    char               buffer[MAX_PKT_LEN];
};
typedef struct dumper dumper_t;

//LIST_HEAD(dumper_list);
struct dumper dumper_list;

/**
 * Procfile handlers
 */
/* file operations for accessing the sessiontab */
static int dumper_procopen(struct inode *inode, struct file *filep);
static ssize_t dumper_procread(struct file *, char __user *, size_t, loff_t *);

static const struct file_operations dumper_fops = {
    .owner   = THIS_MODULE,
    .open    = dumper_procopen,
    .read    = dumper_procread,
};

static int dumper_procopen(struct inode *inode, struct file *filep)
{
    dumper_t *d;

    /* loop through dumpers in the list and find match */
    list_for_each_entry(d, &dumper_list.list, list) {
        if (0 == strncmp(filep->f_path.dentry->d_iname, d->name, MAX_STR)) {
            /* set this descriptors private data pointer to the match */
            filep->private_data = d;
            return 0;
        }
    }

    return -1;
}

ssize_t dumper_procread(struct file *filep,
                        char __user *buf, size_t len, loff_t *ppos)
{
    dumper_t *d = (dumper_t *)filep->private_data;

    /* wait until something is ready */
    if (!d->buffer_len) {
        wait_event_interruptible(d->queue, (0 != d->buffer_len) );
    }

    /* only copy our data if user buf is too long */
    if (len >= d->buffer_len) {
        len = d->buffer_len;
    }

    /* do the copy */
    memcpy(buf, &d->buffer[d->buffer_pos], len);
    d->buffer_len -= len;
    d->buffer_pos += len;

    if (d->buffer_len == 0) {
        d->buffer_pos = 0;
    }

    return len;
}

/**
 * PNA dumper monitor hook
 */
static int dumper_hook(struct session_key *key, int direction,
                        struct sk_buff *skb, unsigned long *info)
{
    dumper_t *d;
    struct pna_packet *pkt;
    struct tcphdr *tcphdr;
    int match;
    unsigned char *base_addr;

    /* bump the skb data pointer back to the ethernet header */
    // XXX: safe???
    // Ugh, who knows about the skb->len
    skb->data = skb_mac_header(skb);

    /* loop over all dumpers and find packet matches */
    list_for_each_entry(d, &dumper_list.list, list) {
        match = sk_run_filter(skb, d->filter, d->filter_len);
        /* look for filter match */
        if (match > 0) {
            /* copy and pass this packet */
            if (!d->buffer_len) {
                d->buffer_len = skb->len + sizeof(*pkt);
                if (d->buffer_len > MAX_PKT_LEN) {
                    d->buffer_len = MAX_PKT_LEN;
                }
                /* copy packet into local buffer */
                pkt = (struct pna_packet *)&d->buffer[0];
                memcpy(&pkt->key, key, sizeof(pkt->key));

                base_addr = skb_mac_header(skb);
                pkt->hdr.eth_hdr = skb_mac_header(skb) - base_addr;
                pkt->hdr.ip_hdr = skb_network_header(skb) - base_addr;
                pkt->hdr.l4_hdr = skb_transport_header(skb) - base_addr;

                /* assume we'll find a payload for now */
                pkt->hdr.payload = pkt->hdr.l4_hdr;
                switch (key->l4_protocol) {
                case IPPROTO_TCP:
                    /* set pointer for TCP */
                    tcphdr = (struct tcphdr *)skb_transport_header(skb);
                    pkt->hdr.payload += (tcphdr->doff * 4);
                    break;
                case IPPROTO_UDP:
                    /* set pointer for UDP */
                    pkt->hdr.payload += sizeof(struct udphdr *);
                    break;
                default:
                    /* reset pointer otherwise */
                    pkt->hdr.payload = 0;
                }
                /* if the payload is not in the buffer, clear the field */
                if (pkt->hdr.payload > skb->len) {
                    pkt->hdr.payload = 0;
                }

                pkt->direction = direction;
                pkt->timestamp = ktime_to_timeval(skb->tstamp);
                pkt->len = skb->len;
                pkt->caplen = d->buffer_len - sizeof(*pkt);
                skb_copy_bits(skb, 0, pkt->data, pkt->caplen);

                /* wake up the queue */
                wake_up_interruptible(&d->queue);
            }
        }
    }

    return 0;
}

#if 0
/**
 * Example periodic cleaner function.
 */
static void dumper_clean(void)
{
    pna_info("pna_dumper: periodic callback\n");
}
#endif

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

/* */
static ssize_t config_show(struct file *file, char __user *buf, size_t len,
                           loff_t *ppos)
{
    dumper_t *d;
    int bytes = 0;

    /* loop over all dumpers and find packet matches */
    list_for_each_entry(d, &dumper_list.list, list) {
        if (len <= 0) {
            break;
        }
        bytes += snprintf(buf, len-bytes, d->name);
        bytes += snprintf(buf, len-bytes, "\n");
    }

    return 0;
}

static ssize_t config_add(struct file *file, const char __user *buf,
                          size_t len, loff_t *ppos)
{
    struct proc_dir_entry *proc_node;
    struct timeval tv;
    int i;
    char *split;
    char *code;
    int filter_len;
    dumper_t *d;
    struct sock_filter *filter;

    /* allocate dumper entry */
    d = (dumper_t *)vmalloc(sizeof(*d));

    /* initilize packet queue */
    init_waitqueue_head(&d->queue);
    memset(d->buffer, 0, MAX_PKT_LEN);
    d->buffer_len = 0;
    d->buffer_pos = 0;

    /* get these from the shared buffer */
    split = strchr(buf, '\n');
    code = split + 1;
    if (split == NULL) {
        pna_err("no filter code\n");
        vfree(d);
        return len;
    }
    *split = '\0';

    i = 0;
    while (split != (buf + i)) {
        if (!isgraph(buf[i])) {
            pna_err("non-printable character in filter name (0x%x)\n", buf[i]);
            return len;
        }
        d->name[i] = buf[i];
        i++;
    }
    d->name[i] = '\0';

    filter = (struct sock_filter *)code;
    filter_len = len - strnlen(d->name, len) - 1;
    filter_len = filter_len / sizeof(*filter);

    /* verify the code */
    d->filter = (struct sock_filter *)vmalloc(filter_len * sizeof(*filter));
    memcpy(d->filter, filter, filter_len * sizeof(*filter));
    d->filter_len = filter_len;
    if (0 != sk_chk_filter(d->filter, d->filter_len)) {
        pna_err("filter code does not verify\n");
        vfree(d->filter);
        vfree(d);
        return len;
    }

    /* create procfile */
    proc_node = create_proc_entry(d->name, 0644, proc_parent);
    if (!proc_node) {
        pna_err("could not create proc entry %s\n", d->name);
        return len;
    }
    proc_node->proc_fops = &dumper_fops;
    proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
    proc_node->uid = 0;
    proc_node->gid = 0;
    proc_node->size = MAX_PKT_LEN;

    /* get the full proc path */
    d->path_len = proc_path(d->path, MAX_STR, proc_node);
    d->path[d->path_len-1] = '\0';

    /* add to list of dumpers */
    list_add_tail(&(d->list), &dumper_list.list);

    /* signal userspace to start polling procfile */
    do_gettimeofday(&tv);
    pna_message_signal(PNA_MSG_METH_POLL, &tv, d->path, d->path_len);

    pna_info("filter %s loaded (%d instructions)\n", d->name, d->filter_len);
    return len;
}

static void dumper_del(dumper_t *d)
{
    struct timeval tv;

    /* signal userspace to stop polling procfile */
    do_gettimeofday(&tv);
    pna_message_signal(PNA_MSG_METH_STOP, &tv, d->path, d->path_len);

    /* destroy procfile */
    remove_proc_entry(d->name, proc_parent);

    /* remove from list */
    list_del(&d->list);

    /* free entry */
    vfree(d->filter);
    vfree(d);
}

static ssize_t config_del(struct file *file, const char __user *buf,
                          size_t len, loff_t *ppos)
{
    struct list_head *pos, *q;
    dumper_t *d;

    pna_info("config_del for: %s (%u)\n", buf, (unsigned int)len);

    /* loop over all dumpers and find packet matches */
    list_for_each_safe(pos, q, &dumper_list.list) {
        d = list_entry(pos, struct dumper, list);
        pna_info("checking for %s == %s\n", d->name, buf);
        if (strncmp(d->name, buf, len+1) == 0) {
            pna_info("match!\n");
            dumper_del(d);
        }
    }

    return len;
}

static int mkproc(char *name, const struct file_operations *fops, int size)
{
    struct proc_dir_entry *proc_node;

    proc_node = create_proc_entry(name, 0644, proc_parent);
    if (!proc_node) {
        pna_err("could not create proc entry %s\n", name);
        return -ENOMEM;
    }
    proc_node->proc_fops = fops;
    proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
    proc_node->uid = 0;
    proc_node->gid = 0;
    proc_node->size = size;

    return 0;
}

static const struct file_operations dumper_add_fops = {
    .owner   = THIS_MODULE,
    .read    = config_show,
    .write   = config_add,
};

static const struct file_operations dumper_del_fops = {
    .owner   = THIS_MODULE,
    .write   = config_del,
};

static int dumper_init(void)
{
    INIT_LIST_HEAD(&dumper_list.list);

    /* create dumper_add and dumper_del proc entries */
    mkproc("dumper_add", &dumper_add_fops, 1);
    mkproc("dumper_del", &dumper_del_fops, 1);

    return 0;
}

static void dumper_release(void)
{
    struct list_head *pos, *q;
    dumper_t *d;

    /* make sure no more entries are straggling */
    list_for_each_safe(pos, q, &dumper_list.list) {
        d = list_entry(pos, struct dumper, list);
        dumper_del(d);
    }

    /* destroy procfiles */
    remove_proc_entry("dumper_add", proc_parent);
    remove_proc_entry("dumper_del", proc_parent);
}
