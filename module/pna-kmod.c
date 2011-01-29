#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "pna.h"

/****************/
/* Memory users */
/****************/

/* configuration parameters */
char *pna_iface = "eth0";
uint pna_prefix = 0xc0a80000; /* 192.168.0.0    */
uint pna_mask = 0xffff0000;   /*            /16 */
uint pna_tables = 2;
uint pna_connections = 0xffffffff;
uint pna_sessions = 0xffffffff;
uint pna_tcp_ports = 0xffffffff;
uint pna_tcp_bytes = 0xffffffff;
uint pna_tcp_packets = 0xffffffff;
uint pna_udp_ports = 0xffffffff;
uint pna_udp_bytes = 0xffffffff;
uint pna_udp_packets = 0xffffffff;
uint pna_ports = 0xffffffff;
uint pna_bytes = 0xffffffff;
uint pna_packets = 0xffffffff;
bool pna_debug = false;

module_param(pna_iface, charp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_iface, "Interface on which we listen to packets");
module_param(pna_prefix, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_prefix, "Network prefix defining 'local' IP addresses");
module_param(pna_mask, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_mask, "Network mask for IP addresses");
module_param(pna_tables, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_tables, "Number of <src,dst,port> tables to use");

module_param(pna_connections, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_connections, "Number of connections to trigger alert");
module_param(pna_sessions, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_sessions, "Number of sessions to trigger alert");
module_param(pna_tcp_ports, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_tcp_ports, "Number of TCP ports to trigger alert");
module_param(pna_tcp_bytes, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_tcp_bytes, "Number of TCP bytes to trigger alert");
module_param(pna_tcp_packets, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_tcp_packets, "Number of TCP packets to trigger alert");
module_param(pna_udp_ports, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_udp_ports, "Number of UDP ports to trigger alert");
module_param(pna_udp_bytes, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_udp_bytes, "Number of UDP bytes to trigger alert");
module_param(pna_udp_packets, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_udp_packets, "Number of TCP packets to trigger alert");
module_param(pna_ports, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_ports, "Number of total ports to trigger alert");
module_param(pna_bytes, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_bytes, "Number of total bytes to trigger alert");
module_param(pna_packets, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_packets, "Number of total packets to trigger alert");

module_param(pna_debug, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(pna_debug, "Enable kernel debug log messages");

/* kernel/user table interaction */
static int utab_open(struct inode *inode, struct file *filep);
static int utab_release(struct inode *inode, struct file *filep);
static int utab_mmap(struct file *filep, struct vm_area_struct *vma);
static const struct file_operations utab_fops = {
    .owner      = THIS_MODULE,
    .open       = utab_open,
    .release    = utab_release,
    .mmap       = utab_mmap,
};

/* we're hooking on to packets with netfilter */
struct nf_hook_ops nf_ops = {
    .hook = pna_packet_hook,
    .owner = THIS_MODULE,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

/* per-table information */
struct utab_info *utab_info;

/* pointer to the /proc durectiry parent node */
static struct proc_dir_entry *proc_parent;

static void utab_clean(struct utab_info *info);
static int __init pna_init(void);
static void __exit pna_exit(void);

/*
 * kernel/user table interaction
 */
/* runs when user space has opened the file */
static int utab_open(struct inode *inode, struct file *filep)
{
    int i;
    struct utab_info *info;

    try_module_get(THIS_MODULE);

    /* find the name of file opened (index into utab_info) */
    sscanf(filep->f_path.dentry->d_iname, PNA_PROCFILE, &i);
    info = &utab_info[i];
    if (!info->table_dirty) {
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
static int utab_release(struct inode *inode, struct file *filep)
{
    int i;
    struct utab_info *info;

    /* find the name of file opened (index into utab_info) */
    sscanf(filep->f_path.dentry->d_iname, PNA_PROCFILE, &i);
    info = &utab_info[i];

    /* zero out the table */
    memset(info->table_base, 0, PNA_TABLE_SIZE);

    /* this table is safe to use again */
    utab_clean(info);

    /* unlock this table, has the effect of being free for use again */
    mutex_unlock(&info->read_mutex);

    module_put(THIS_MODULE);
    return 0;
}

/* runs when user space wants to mmap the file */
static int utab_mmap(struct file *filep, struct vm_area_struct *vma)
{
    unsigned long utab_pfn;
    unsigned long size;
    struct utab_info *info = filep->private_data;

    utab_pfn = page_to_pfn(virt_to_page(info->table_base));

    size = vma->vm_end - vma->vm_start;
    if (size > PNA_TABLE_SIZE) {
        return -EIO;
    }

    if (remap_pfn_range(vma, vma->vm_start, utab_pfn, size,
                vma->vm_page_prot)) {
        printk("remap_pfn_range failed\n");
        return -EAGAIN;
    }
    return 0;
}

/* clear out all the mutable data from a utab entry */
static void utab_clean(struct utab_info *info)
{
    info->table_dirty = 0;
    info->smp_id = 0;
    memset(info->iface, 0, PNA_MAX_STR);
    info->nlips = 0;
    info->nrips = 0;
    info->nports = 0;
    info->nlips_missed = 0;
    info->nrips_missed = 0;
    info->nports_missed = 0;
}

/*
 * Module oriented code
 */
/* cleanup and exit/error */
#define __ALL    0
#define __ALERTS 1
#define __HOOK   2
#define __TABLES 3
#define __INFO   4
static void pna_cleanup(int start)
{
    int i;

    switch (start)
    {
    case __ALL:
    case __ALERTS:
        pna_alert_cleanup();
    case __HOOK:
        /* remove the packet hook */
        nf_unregister_hook(&nf_ops);
    case __TABLES:
        /* destroy each table file we created */
        for (i = pna_tables - 1; i >= 0; i--) {
            if (utab_info[i].table_name[0] != '\0') {
                remove_proc_entry(utab_info[i].table_name, proc_parent);
            }
            if (utab_info[i].table_base != NULL) {
                kfree(utab_info[i].table_base);
            }
        }
    case __INFO:
        /* free up table meta-information struct */
        vfree(utab_info);
        /* destroy /proc directory */
        remove_proc_entry(PNA_PROCDIR, NULL);
    }
}

/* Initialization hook */
static int __init pna_init(void)
{
    int i;
    uint offset;
    char table_str[PNA_MAX_STR];
    static struct proc_dir_entry *proc_node;
    struct utab_info *info;
    int ret = 0;

    /* create the /proc base dir for pna tables */
    proc_parent = proc_mkdir(PNA_PROCDIR, NULL);

    /* make memory for table meta-information */
    utab_info = (struct utab_info *)
                    vmalloc(pna_tables * sizeof(struct utab_info));
    if (!utab_info) {
        printk("insufficient memory for utab_info\n");
        pna_cleanup(__INFO);
        return -ENOMEM;
    }
    memset(utab_info, 0, pna_tables * sizeof(struct utab_info));

    /* configure each table for use */
    for (i = 0; i < pna_tables; i++) {
        info = &utab_info[i];
        info->table_base = kzalloc(PNA_TABLE_SIZE, GFP_KERNEL);
        if (!info->table_base) {
            printk("insufficient memory for %d tables (%lu bytes)\n",
                    pna_tables, (pna_tables * PNA_TABLE_SIZE));
            pna_cleanup(__TABLES);
            return -ENOMEM;
        }
        /* set up table pointers */
        offset = 0;
        info->lips = info->table_base + offset;
        offset += PNA_SZ_LIP_ENTRIES;
        info->rips = info->table_base + offset;
        offset += PNA_SZ_RIP_ENTRIES;
        info->ports[PNA_PROTO_TCP] = info->table_base + offset;
        offset += PNA_SZ_PORT_ENTRIES;
        info->ports[PNA_PROTO_UDP] = info->table_base + offset;
        offset += PNA_SZ_PORT_ENTRIES;
        utab_clean(info);

        /* initialize the read_mutec */
        mutex_init(&info->read_mutex);

        snprintf(table_str, PNA_MAX_STR, PNA_PROCFILE, i);
        strncpy(info->table_name, table_str, PNA_MAX_STR);
        proc_node = create_proc_entry(info->table_name, 0644, proc_parent);
        if (!proc_node) {
            printk("failed to make proc entry: %s\n", table_str);
            pna_cleanup(__TABLES);
            return -ENOMEM;
        }
        proc_node->proc_fops = &utab_fops;
        proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
        proc_node->uid = 0;
        proc_node->gid = 0;
        proc_node->size = PNA_TABLE_SIZE;
    }

    /* everything is set up, register the packet hook */
    nf_register_hook(&nf_ops);

    if (pna_alert_init() < 0) {
        pna_cleanup(__ALERTS);
        return -1;
    }

    printk("PNA module is initialized\n");

    return ret;
}

/* Destruction hook */
static void __exit pna_exit(void)
{
    pna_cleanup(__ALL);
    printk("PNA module is inactive\n");
}

module_init(pna_init);
module_exit(pna_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
