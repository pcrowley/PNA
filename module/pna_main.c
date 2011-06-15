/* main PNA initialization (where the kernel module starts) */
/* functions: pna_init, pna_cleanup, pna_hook */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/jiffies.h>

#include <net/ip.h>
#include <net/tcp.h>

#include "pna.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
    typedef struct rtnl_link_stats64 pna_link_stats;
    typedef unsigned long long  pna_stat_uword;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
    typedef const struct net_device_stats *pna_link_stats;
    typedef unsigned long pna_stat_uword;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37) */

struct pna_nstime {
    unsigned long long min;
    unsigned long long max;
    unsigned long long sum;
};

/* for performance measurement */
struct pna_perf {
    __u64 t_jiffies; /* 8 */
    struct timeval currtime; /* 8 */
    struct timeval prevtime; /* 8 */
    __u32 p_interval[PNA_DIRECTIONS]; /* 8 */
    __u32 B_interval[PNA_DIRECTIONS]; /* 8 */
    pna_stat_uword dev_last_rx;
    pna_stat_uword dev_last_fifo;

    struct pna_nstime flow_ns;
    struct pna_nstime decode_ns;
};

DEFINE_PER_CPU(struct pna_perf, perf_data);

/* taken from linux/jiffies.h in kernel v2.6.21 */
#ifndef time_after_eq64
# define time_after_eq64(a,b) \
   (typecheck(__u64,a) && typecheck(__u64,b) && ((__s64)(a)-(__s64)(b)>=0))
#endif
#define PERF_INTERVAL      10

static void pna_nslog(struct timespec *start, struct timespec *stop, struct pna_nstime *ns);
static void pna_perflog(struct sk_buff *skb, int dir, struct net_device *dev);
static int pna_localize(struct pna_flowkey *key, int *direction);
static int pna_done(struct sk_buff *skb);
int pna_hook(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev);
static int __init pna_init(void);
static void pna_cleanup(void);

/* define a new packet type to hook on */
static struct packet_type pna_packet_type = {
    .type = htons(ETH_P_ALL),
    .func = pna_hook,
    .dev = NULL,
};

/* general non-kernel hash function for double hashing */
unsigned int pna_hash(unsigned int key, int bits)
{
    unsigned int hash = key;

    /* lets take the highest bits */
    hash = key >> (sizeof(unsigned int) - bits);

    /* divide by 2 and make it odd */
    hash = (hash >> 1) | 0x01;

    return hash;
}

/**
 * Receive Packet Hook (and helpers)
 */
/* make sure the local and remote values are correct in the key */
static int pna_localize(struct pna_flowkey *key, int *direction)
{
    unsigned int temp;

    /* test local_ip against pna_prefix/pna_mask */
    temp = key->local_ip & pna_mask;
    if (temp == (pna_prefix & pna_mask)) {
        /* local ip is local! */
        *direction = PNA_DIR_OUTBOUND;

        return 1;
    }

    /* test if remote_ip is actually local */
    temp = key->remote_ip & pna_mask;
    if (temp == (pna_prefix & pna_mask)) {
        /* remote_ip is local, swap! */
        *direction = PNA_DIR_INBOUND;

        temp = key->local_ip;
        key->local_ip = key->remote_ip;
        key->remote_ip = temp;

        temp = key->local_port;
        key->local_port = key->remote_port;
        key->remote_port = temp;

        return 1;
    }

    return 0;
}

/* free all te resources we've used */
static int pna_done(struct sk_buff *skb)
{
    kfree_skb(skb);
    return NET_RX_DROP;
}

/* per-packet hook that begins pna processing */
int pna_hook(struct sk_buff *skb, struct net_device *dev,
        struct packet_type *pt, struct net_device *orig_dev)
{
    struct pna_flowkey key;
    struct ethhdr *ethhdr;
    struct iphdr *iphdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    int ret, direction;

    struct timespec start, stop;
    struct pna_perf *perf = &get_cpu_var(perf_data);
    
    /* we don't care about outgoing packets */
    if (skb->pkt_type == PACKET_OUTGOING) {
        return pna_done(skb);
    }

    /* only our software deals with *dev, no one else should care about skb */
    /* (also greatly imrpoves performance since ip_input doesn't do much) */
    skb->pkt_type = PACKET_OTHERHOST;
    
    /* make sure we have the skb exclusively */
    if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
        /* non-exclusive and couldn't clone, must drop */ 
        return NET_RX_DROP;
    }

    getnstimeofday(&start);
	/* make sure the key is all zeros before we start */
	memset(&key, 0, sizeof(key));
    
    /* we now have exclusive access, so let's decode the skb */
    ethhdr = eth_hdr(skb);
    key.l3_protocol = ntohs(ethhdr->h_proto);
    
    switch (key.l3_protocol) {
    case ETH_P_IP:
        /* this is a supported type, continue */
        iphdr = ip_hdr(skb);
        /* assume for now that src is local */
        key.local_ip = ntohl(iphdr->saddr);
        key.remote_ip = ntohl(iphdr->daddr);
        key.l4_protocol = iphdr->protocol;

        skb_set_transport_header(skb, ip_hdrlen(skb));
        switch (key.l4_protocol) {
        case IPPROTO_TCP:
            tcphdr = tcp_hdr(skb);
            key.local_port = ntohs(tcphdr->source);
            key.remote_port = ntohs(tcphdr->dest);
            break;
        case IPPROTO_UDP:
            udphdr = udp_hdr(skb);
            key.local_port = ntohs(udphdr->source);
            key.remote_port = ntohs(udphdr->dest);
            break;
        default:
            return pna_done(skb);
        }
        break;
    default:
        return pna_done(skb);
    }

    /* entire key should now be filled in and we have a flow, localize it */
    if (!pna_localize(&key, &direction)) {
        /* couldn't localize the IP (neither source nor dest in prefix) */
        return pna_done(skb);
    }
    getnstimeofday(&stop);
    pna_nslog(&start, &stop, &perf->decode_ns);

    /* log performance data */
    if (pna_perfmon) {
        pna_perflog(skb, direction, dev);
    }

    /* insert into flow table */
    if (pna_flowmon == true) {
        getnstimeofday(&start);
        ret = flowmon_hook(&key, direction, skb);
        getnstimeofday(&stop);
        if (ret < 0) {
            /* failed to insert -- cleanup */
            return pna_done(skb);
        }
        pna_nslog(&start, &stop, &perf->flow_ns);

        /* run real-time hooks */
        if (pna_rtmon == true) {
            rtmon_hook(&key, direction, skb, (unsigned long)ret);
#ifdef PIPELINE_MODE
            /* if we're running in pipeline mode, don't kill the packet */
            return NET_RX_DROP;
#endif /* PIPELINE_MODE */
        }
    }

    /* free our skb */
    return pna_done(skb);
}

static void pna_nslog(struct timespec *start, struct timespec *stop, struct pna_nstime *ns)
{
    unsigned long long ns_diff;

    ns_diff = ((stop->tv_sec - start->tv_sec) * 1000000000);
    ns_diff += (stop->tv_nsec - start->tv_nsec);
    ns->sum += ns_diff;

    if (ns_diff < ns->min) {
        ns->min = ns_diff;
    }
    if (ns_diff > ns->max) {
        ns->max = ns_diff;
    }
}

/**
 * Performance Monitoring
 */
static void pna_perflog(struct sk_buff *skb, int dir, struct net_device *dev)
{
    __u32 t_interval;
    __u32 fps_in, Mbps_in, avg_in;
    __u32 fps_out, Mbps_out, avg_out;
    pna_link_stats stats;
    __u32 frame_count;
    struct pna_perf *perf = &get_cpu_var(perf_data);


    /* time_after_eq64(a,b) returns true if time a >= time b. */
    if ( time_after_eq64(get_jiffies_64(), perf->t_jiffies) ) {

        /* get sampling interval time */
        do_gettimeofday(&perf->currtime);
        t_interval = perf->currtime.tv_sec - perf->prevtime.tv_sec;
        /* update for next round */
        perf->prevtime = perf->currtime;

        /* calculate the numbers */
        fps_in = perf->p_interval[PNA_DIR_INBOUND] / t_interval;
        /* 125000 Mb = (1000 MB/KB * 1000 KB/B) / 8 bits/B */
        Mbps_in = perf->B_interval[PNA_DIR_INBOUND] / 125000 / t_interval;
        avg_in = 0;
        if (perf->p_interval[PNA_DIR_INBOUND] != 0) {
            avg_in = perf->B_interval[PNA_DIR_INBOUND];
            avg_in /= perf->p_interval[PNA_DIR_INBOUND];
            /* take away non-Ethernet packet measured */
            avg_in -= (ETH_INTERFRAME_GAP + ETH_PREAMBLE);
        }

        fps_out = perf->p_interval[PNA_DIR_OUTBOUND] / t_interval;
        /* 125000 Mb = (1000 MB/KB * 1000 KB/B) / 8 bits/B */
        Mbps_out = perf->B_interval[PNA_DIR_OUTBOUND] / 125000 / t_interval;
        avg_out = 0;
        if (perf->p_interval[PNA_DIR_OUTBOUND] != 0) {
            avg_out = perf->B_interval[PNA_DIR_OUTBOUND];
            avg_out /= perf->p_interval[PNA_DIR_OUTBOUND];
            /* take away non-Ethernet packet measured */
            avg_out -= (ETH_INTERFRAME_GAP + ETH_PREAMBLE);
        }

        /* report the numbers */
        if (fps_in + fps_out > 1000) {
            pr_info("pna throughput smpid:%d, "
                    "in:{fps:%u,Mbps:%u,avg:%u}, "
                    "out:{fps:%u,Mbps:%u,avg:%u}\n", smp_processor_id(),
                    fps_in, Mbps_in, avg_in, fps_out, Mbps_out, avg_out);

            frame_count = perf->p_interval[PNA_DIR_OUTBOUND];
            frame_count += perf->p_interval[PNA_DIR_INBOUND];
            pr_info("pna decode time:{min:%llu,avg:%llu,max:%llu}\n",
                    perf->decode_ns.min, perf->decode_ns.sum / frame_count,
                    perf->decode_ns.max);
            pr_info("pna flow time:{min:%llu,avg:%llu,max:%llu}\n",
                    perf->flow_ns.min, perf->flow_ns.sum / frame_count,
                    perf->flow_ns.max);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
            /* numbers from the NIC */
            dev_get_stats(dev, &stats);
            pr_info("pna rx_stats: packets:%llu, fifo_errors:%llu\n",
                    stats.rx_packets - perf->dev_last_rx,
                    stats.rx_fifo_errors - perf->dev_last_fifo);
            perf->dev_last_rx = stats.rx_packets;
            perf->dev_last_fifo = stats.rx_fifo_errors;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
            /* numbers from the NIC */
            stats = dev_get_stats(dev);
            pr_info("pna rx_stats: packets:%lu, fifo_errors:%lu\n",
                    stats->rx_packets - perf->dev_last_rx,
                    stats->rx_fifo_errors - perf->dev_last_fifo);
            perf->dev_last_rx = stats->rx_packets;
            perf->dev_last_fifo = stats->rx_fifo_errors;
#endif /* LINUX_VERSION_CODE */
        }

        perf->flow_ns.min = -1;
        perf->flow_ns.sum = 0;
        perf->flow_ns.max = 0;
        perf->decode_ns.min = -1;
        perf->decode_ns.sum = 0;
        perf->decode_ns.max = 0;

        /* set updated counters */
        perf->p_interval[PNA_DIR_INBOUND] = 0;
        perf->B_interval[PNA_DIR_INBOUND] = 0;
        perf->p_interval[PNA_DIR_OUTBOUND] = 0;
        perf->B_interval[PNA_DIR_OUTBOUND] = 0;
        perf->t_jiffies = msecs_to_jiffies(PERF_INTERVAL*MSEC_PER_SEC);
        perf->t_jiffies += get_jiffies_64();
    }

    /* increment packets seen in this interval */
    perf->p_interval[dir]++;
    perf->B_interval[dir] += skb->len + ETH_OVERHEAD;
}

/*
 * Module oriented code
 */
/* Initialization hook */
int __init pna_init(void)
{
    int ret = 0;

    /* set up the flow table(s) */
    if ((ret = flowmon_init()) < 0) {
        return ret;
    }

    /* set up the alert system */
    if (pna_alert_init() < 0) {
        pna_cleanup();
        return -1;
    }

    if (rtmon_init() < 0) {
        pna_alert_cleanup();
        pna_cleanup();
        return -1;
    }

    /* everything is set up, register the packet hook */
    pna_packet_type.dev = dev_get_by_name(&init_net, pna_iface);
    dev_add_pack(&pna_packet_type);

    pr_info("pna: module is initialized\n");
#ifdef PIPELINE_MODE
    pr_info("pna: (in pipeline mode)\n");
#endif /* PIPELINE_MODE */

    return ret;
}

/* Destruction hook */
void pna_cleanup(void)
{
    dev_remove_pack(&pna_packet_type);
    rtmon_release();
    pna_alert_cleanup();
    flowmon_cleanup();
    pr_info("pna: module is inactive\n");
}

module_init(pna_init);
module_exit(pna_cleanup);
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
