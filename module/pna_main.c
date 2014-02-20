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

/* main PNA initialization (where the kernel module starts) */
/* functions: pna_init, pna_cleanup, pna_hook */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/hash.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/netdevice.h>
#include <linux/if.h>

#include <linux/jiffies.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sctp.h>

#include "pna.h"

static void pna_perflog(struct sk_buff *skb, int dir);
static int pna_localize(struct pna_flowkey *key, int *direction);
static int pna_done(struct sk_buff *skb);
int pna_hook(struct sk_buff *skb, struct net_device *dev,
	     struct packet_type *pt, struct net_device *orig_dev);
static int __init pna_init(void);
static void pna_cleanup(void);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
typedef const struct net_device_stats *pna_link_stats;
typedef unsigned long pna_stat_uword;
#else
typedef struct rtnl_link_stats64 pna_link_stats;
typedef unsigned long long pna_stat_uword;
#endif                          /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37) */

/* define a new packet type to hook on */
#define PNA_MAXIF 4
static struct packet_type pna_packet_type[PNA_MAXIF] = {
	{ .type = htons(ETH_P_ALL), .func = pna_hook, .dev = NULL, },
	{ .type = htons(ETH_P_ALL), .func = pna_hook, .dev = NULL, },
	{ .type = htons(ETH_P_ALL), .func = pna_hook, .dev = NULL, },
	{ .type = htons(ETH_P_ALL), .func = pna_hook, .dev = NULL, },
};

/* define a fragment table for reconstruction */
#define PNA_MAXFRAGS 8
struct pna_frag {
	unsigned long fingerprint;
	unsigned short src_port;
	unsigned short dst_port;
};
static struct pna_frag pna_frag_table[PNA_MAXFRAGS];
static int pna_frag_next_idx = 0;

/* for performance measurement */
struct pna_perf {
	__u64 t_jiffies;                        /* 8 */
	struct timeval currtime;                /* 8 */
	struct timeval prevtime;                /* 8 */
	__u32 p_interval[PNA_DIRECTIONS];       /* 8 */
	__u32 B_interval[PNA_DIRECTIONS];       /* 8 */
	pna_stat_uword dev_last_rx[PNA_MAXIF];
	pna_stat_uword dev_last_fifo[PNA_MAXIF];
};

DEFINE_PER_CPU(struct pna_perf, perf_data);

/* taken from linux/jiffies.h in kernel v2.6.21 */
#ifndef time_after_eq64
#define time_after_eq64(a, b) \
	(typecheck(__u64, a) && typecheck(__u64, b) && ((__s64)(a) - (__s64)(b) >= 0))
#endif
#define PERF_INTERVAL      10

/* handle IP fragmented packets */
unsigned long pna_frag_hash(struct iphdr *iphdr)
{
	unsigned long hash = 0;

	/* note: don't care about byte ordering here since we're hashing */
	hash ^= hash_32(iphdr->saddr, 32);
	hash ^= hash_32(iphdr->daddr, 32);
	hash ^= (hash_32(iphdr->protocol, 16) << 16);
	hash ^= hash_32(iphdr->id, 16);
	return hash;
}

struct pna_frag *pna_get_frag(struct iphdr *iphdr)
{
	int i;
	struct pna_frag *entry;
	unsigned long fingerprint = pna_frag_hash(iphdr);

	for (i = 0; i < PNA_MAXFRAGS; i++) {
		entry = &pna_frag_table[i];
		if (fingerprint == entry->fingerprint)
			return entry;
	}

	return NULL;
}

void pna_set_frag(struct iphdr *iphdr,
		  unsigned short src_port, unsigned short dst_port)
{
	/* this is in the handler, so it is serial (for now) */
	struct pna_frag *entry;

	/* grab the entry to update */
	entry = &pna_frag_table[pna_frag_next_idx];
	/* increment to next index to use */
	pna_frag_next_idx = (pna_frag_next_idx + 1) % PNA_MAXFRAGS;
	/* update the entry */
	entry->fingerprint = pna_frag_hash(iphdr);
	entry->src_port = src_port;
	entry->dst_port = dst_port;
}

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

void pna_session_swap(struct pna_flowkey *key)
{
	unsigned int temp;

	temp = key->local_ip;
	key->local_ip = key->remote_ip;
	key->remote_ip = temp;

	temp = key->local_port;
	key->local_port = key->remote_port;
	key->remote_port = temp;

	temp = key->local_domain;
	key->local_domain = key->remote_domain;
	key->remote_domain = temp;
}

/**
 * Receive Packet Hook (and helpers)
 */
/* make sure the local and remote values are correct in the key */
static int pna_localize(struct pna_flowkey *key, int *direction)
{
	key->local_domain = pna_dtrie_lookup(key->local_ip);
	key->remote_domain = pna_dtrie_lookup(key->remote_ip);

	/* the lowest domain ID is treated as local */
	if (key->local_domain < key->remote_domain) {
		/* local ip is local */
		*direction = PNA_DIR_OUTBOUND;
		return 1;
	} else if (key->local_domain > key->remote_domain) {
		/* remote ip is smaller, swap! */
		*direction = PNA_DIR_INBOUND;
		pna_session_swap(key);
		return 1;
	} else {
		/* neither of these are local, weird and drop */
		if (key->local_domain == MAX_DOMAIN)
			return 0;
		/* local and remote are in same domain, tie break */
		/* (assume IPs are different) */
		if (key->local_ip < key->remote_ip) {
			/* local IP is smaller */
			*direction = PNA_DIR_OUTBOUND;
			return 1;
		} else {
			/* remote IP is smaller, swap */
			*direction = PNA_DIR_INBOUND;
			pna_session_swap(key);
			return 1;
		}
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
	struct pna_frag *entry;
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	struct sctphdr *sctphdr;
	unsigned short src_port, dst_port, frag_off;
	int ret, direction, offset;

	/* we don't care about outgoing packets */
	if (skb->pkt_type == PACKET_OUTGOING)
		return pna_done(skb);

	/* only our software deals with *dev, no one else should care about skb */
	/* (also greatly imrpoves performance since ip_input doesn't do much) */
	skb->pkt_type = PACKET_OTHERHOST;

	/* make sure we have the skb exclusively */
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
		/* non-exclusive and couldn't clone, must drop */
		return NET_RX_DROP;

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

		/* check if there are fragments */
		frag_off = ntohs(iphdr->frag_off);
		offset = frag_off & IP_OFFSET;

		skb_set_transport_header(skb, ip_hdrlen(skb));
		switch (key.l4_protocol) {
		case IPPROTO_TCP:
			if (offset != 0) {
				pr_warn("Unknown IP-fragmented TCP, dropping");
				return pna_done(skb);
			}
			tcphdr = tcp_hdr(skb);
			key.local_port = ntohs(tcphdr->source);
			key.remote_port = ntohs(tcphdr->dest);
			break;
		case IPPROTO_UDP:
			/* this is an IP fragmented UDP packet */
			if (offset != 0) {
				/* offset is set, get the appropriate entry */
				entry = pna_get_frag(iphdr);
				if (!entry) {
					pr_warn("Unknown IP-fragmented UDP, dropping");
					return pna_done(skb);
				}
				src_port = entry->src_port;
				dst_port = entry->dst_port;
			} else {
				/* no offset */
				udphdr = udp_hdr(skb);
				src_port = ntohs(udphdr->source);
				dst_port = ntohs(udphdr->dest);
				/* there will be fragments, add to table */
				if (frag_off & IP_MF)
					pna_set_frag(iphdr, src_port, dst_port);
			}
			key.local_port = src_port;
			key.remote_port = dst_port;
			break;
		case IPPROTO_SCTP:
			if (offset != 0) {
				pr_warn("Unknown IP-fragmented SCTP, dropping");
				return pna_done(skb);
			}
			sctphdr = sctp_hdr(skb);
			key.local_port = ntohs(sctphdr->source);
			key.remote_port = ntohs(sctphdr->dest);
			break;
			break;
		default:
			return pna_done(skb);
		}
		break;
	default:
		return pna_done(skb);
	}

	/* entire key should now be filled in and we have a flow, localize it */
	if (!pna_localize(&key, &direction))
		/* couldn't localize the IP (neither source nor dest in prefix) */
		return pna_done(skb);

	/* log performance data */
	if (pna_perfmon)
		pna_perflog(skb, direction);

	/* hook actions here */

	/* insert into flow table */
	if (pna_flowmon == true) {
		ret = flowmon_hook(&key, direction, skb);
		if (ret < 0)
			/* failed to insert -- cleanup */
			return pna_done(skb);

		/* run real-time hooks */
		if (pna_rtmon == true)
			rtmon_hook(&key, direction, skb, (unsigned long)ret);
	}

	/* free our skb */
	return pna_done(skb);
}

/**
 * Performance Monitoring
 */
static void pna_perflog(struct sk_buff *skb, int dir)
{
	__u32 t_interval;
	__u32 fps_in, Mbps_in, avg_in;
	__u32 fps_out, Mbps_out, avg_out;
	pna_link_stats stats;
	int i;
	struct net_device *dev;
	struct pna_perf *perf = &get_cpu_var(perf_data);


	/* time_after_eq64(a,b) returns true if time a >= time b. */
	if (time_after_eq64(get_jiffies_64(), perf->t_jiffies)) {

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
		Mbps_out =
			perf->B_interval[PNA_DIR_OUTBOUND] / 125000 / t_interval;
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

			for (i = 0; i < PNA_MAXIF; i++) {
				dev = pna_packet_type[i].dev;
				if (dev == NULL)
					break;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 34)
				/* numbers from the NIC */
				stats = dev_get_stats(dev);
				pr_info
					("pna %s rx_stats: packets:%lu, fifo_overruns:%lu\n",
					dev->name, stats->rx_packets - perf->dev_last_rx[i],
					stats->rx_fifo_errors - perf->dev_last_fifo[i]);
				perf->dev_last_rx[i] = stats->rx_packets;
				perf->dev_last_fifo[i] = stats->rx_fifo_errors;
#else
				/* numbers from the NIC */
				dev_get_stats(dev, &stats);
				pr_info
					("pna %s rx_stats: packets:%llu, fifo_overruns:%llu\n",
					dev->name, stats.rx_packets - perf->dev_last_rx[i],
					stats.rx_fifo_errors - perf->dev_last_fifo[i]);
				perf->dev_last_rx[i] = stats.rx_packets;
				perf->dev_last_fifo[i] = stats.rx_fifo_errors;
#endif                          /* LINUX_VERSION_CODE */
			}
		}

		/* set updated counters */
		perf->p_interval[PNA_DIR_INBOUND] = 0;
		perf->B_interval[PNA_DIR_INBOUND] = 0;
		perf->p_interval[PNA_DIR_OUTBOUND] = 0;
		perf->B_interval[PNA_DIR_OUTBOUND] = 0;
		perf->t_jiffies = msecs_to_jiffies(PERF_INTERVAL * MSEC_PER_SEC);
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
	char *next = pna_iface;
	int i;
	int ret = 0;

	/* set up the flow table(s) */
	if ((ret = flowmon_init()) < 0)
		return ret;
	//init the domain mappings must be called after flowmon_init because of initialization of PNA proc entry
	pna_dtrie_init();

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
	for (i = 0; (i < PNA_MAXIF) && (next != NULL); i++) {
		next = strnchr(pna_iface, IFNAMSIZ, ',');
		if (NULL != next)
			*next = '\0';
		pr_info("pna: capturing on %s", pna_iface);
		pna_packet_type[i].dev = dev_get_by_name(&init_net, pna_iface);
		dev_add_pack(&pna_packet_type[i]);
		pna_iface = next + 1;
	}

#ifdef PIPELINE_MODE
	next = "(in pipeline mode)";
#else
	next = "";
#endif                          /* PIPELINE_MODE */

	pr_info("pna: module is initialized %s\n", next);

	return ret;
}

/* Destruction hook */
void pna_cleanup(void)
{
	int i;

	for (i = 0; (i < PNA_MAXIF) && (pna_packet_type[i].dev != NULL); i++) {
		dev_remove_pack(&pna_packet_type[i]);
		pr_info("pna: released %s\n", pna_packet_type[i].dev->name);
	}
	rtmon_release();
	pna_alert_cleanup();
	//dtrie deinit should be called before flowmon_cleanup for proc file reasons
	pna_dtrie_deinit();
	flowmon_cleanup();
	pr_info("pna: module is inactive\n");
}

module_init(pna_init);
module_exit(pna_cleanup);
MODULE_LICENSE("Apache 2.0");
MODULE_AUTHOR("Michael J. Schultz <mjschultz@gmail.com>");
