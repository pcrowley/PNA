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

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#define __FAVOR_BSD
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "pna.h"

static void pna_perflog(char *pkt, int dir);
static int pna_localize(struct pna_flowkey *key, int *direction);
static int pna_done(const unsigned char *pkt);
int pna_init(void);
void pna_cleanup(void);

typedef unsigned long pna_stat_uword;

#define eth_hdr(pkt) (struct ether_header *)(pkt)
#define ip_hdr(pkt) (struct ip *)(pkt)
#define tcp_hdr(pkt) (struct tcphdr *)(pkt)
#define udp_hdr(pkt) (struct udphdr *)(pkt)

/* define a fragment table for reconstruction */
#define PNA_MAXFRAGS 512
struct pna_frag {
	unsigned long fingerprint;
	unsigned short src_port;
	unsigned short dst_port;
};
static struct pna_frag pna_frag_table[PNA_MAXFRAGS];
static int pna_frag_next_idx = 0;
static int pna_frag_packets_missed = 0;
static int pna_frag_bytes_missed = 0;

/* taken from linux/jiffies.h in kernel v2.6.21 */
#ifndef time_after_eq64
#define time_after_eq64(a, b) \
	(typecheck(__u64, a) && typecheck(__u64, b) && ((__s64)(a) - (__s64)(b) >= 0))
#endif
#define PERF_INTERVAL      10

#define GOLDEN_RATIO_PRIME_32  0x9e370001UL

unsigned int hash_32(unsigned int val, unsigned int bits)
{
    unsigned int hash = val * GOLDEN_RATIO_PRIME_32;
    return hash >> (32 - bits);
}

/* handle IP fragmented packets */
unsigned long pna_frag_hash(struct ip *iphdr)
{
	unsigned long hash = 0;

	/* note: don't care about byte ordering here since we're hashing */
	hash ^= hash_32(iphdr->ip_src.s_addr, 32);
	hash ^= hash_32(iphdr->ip_dst.s_addr, 32);
	hash ^= (hash_32(iphdr->ip_p, 16) << 16);
	hash ^= hash_32(iphdr->ip_id, 16);
	return hash;
}

struct pna_frag *pna_get_frag(struct ip *iphdr)
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

void pna_set_frag(struct ip *iphdr,
		  unsigned short src_port, unsigned short dst_port)
{
	/* this is in the handler, so it is serial (for now) */
	struct pna_frag *entry;

	/* verify fragment doesn't already exist */
	entry = pna_get_frag(iphdr);
	if (entry)
		return;

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
static int pna_done(const unsigned char *pkt)
{
	return NET_RX_DROP;
}

/* per-packet hook that begins pna processing */
int pna_hook(unsigned int pkt_len, const struct timeval tv, const unsigned char *pkt)
{
	struct pna_flowkey key;
	struct pna_frag *entry;
	struct ether_header *ethhdr;
	struct ip *iphdr;
	struct tcphdr *tcphdr;
	struct udphdr *udphdr;
	unsigned short src_port, dst_port, frag_off, flags;
	int ret, direction, offset, bump;

	/* make sure the key is all zeros before we start */
	memset(&key, 0, sizeof(key));

	/* by default assume no flags */
	flags = 0;

	/* we now have exclusive access, so let's decode the pkt */
	ethhdr = eth_hdr(pkt);
	key.l3_protocol = ntohs(ethhdr->ether_type);

    /* we don't care about VLAN tag(s)s - there may be multiple level */
    if (key.l3_protocol == ETHERTYPE_VLAN) {
        bump = 4;
    }

    // bump the pkt pointer for ethernet
    pkt = sizeof(struct ether_header) + pkt + bump;
	switch (key.l3_protocol) {
	case ETHERTYPE_IP:
		/* this is a supported type, continue */
		iphdr = ip_hdr(pkt);
		/* assume for now that src is local */
		key.l4_protocol = iphdr->ip_p;
		key.local_ip = ntohl(iphdr->ip_src.s_addr);
		key.remote_ip = ntohl(iphdr->ip_dst.s_addr);

		/* check if there are fragments */
		frag_off = ntohs(iphdr->ip_off);
		offset = frag_off & IP_OFFMASK;

        // bump the pkt pointer for ip
        pkt = pkt + sizeof(struct ip);
		switch (key.l4_protocol) {
		case IPPROTO_TCP:
			if (offset != 0) {
                printf("ipproto_tcp, offset: %d\n", offset);
				return pna_done(pkt);
            }
			tcphdr = tcp_hdr(pkt);
			key.local_port = ntohs(tcphdr->th_sport);
			key.remote_port = ntohs(tcphdr->th_dport);
			flags = tcphdr->th_flags;
			break;
		case IPPROTO_UDP:
			/* this is an IP fragmented UDP packet */
			if (offset != 0) {
				/* offset is set, get the appropriate entry */
				entry = pna_get_frag(iphdr);
				/* no entry means we can't record - UDP can arrive out of order */
				if (!entry) {
					pna_frag_packets_missed += 1;
					pna_frag_bytes_missed += pkt_len + ETH_OVERHEAD;
					return pna_done(pkt);
				}
				src_port = entry->src_port;
				dst_port = entry->dst_port;
			} else {
				/* no offset */
				udphdr = udp_hdr(pkt);
				src_port = ntohs(udphdr->uh_sport);
				dst_port = ntohs(udphdr->uh_dport);
				/* there will be fragments, add to table */
				if (frag_off & IP_MF)
					pna_set_frag(iphdr, src_port, dst_port);
			}
			key.local_port = src_port;
			key.remote_port = dst_port;
			break;
		default:
            printf("unknown ipproto: %d\n", key.l4_protocol);
			return pna_done(pkt);
		}
		break;
	default:
		return pna_done(pkt);
	}

	/* entire key should now be filled in and we have a flow, localize it */
	if (!pna_localize(&key, &direction))
		/* couldn't localize the IP (neither source nor dest in prefix) */
		return pna_done(pkt);

	/* hook actions here */

	/* insert into flow table */
	if (pna_flowmon == true) {
		ret = flowmon_hook(&key, direction, flags, pkt, pkt_len, tv);
		if (ret < 0)
			/* failed to insert -- cleanup */
			return pna_done(pkt);

		/* run real-time hooks */
		if (pna_rtmon == true)
			rtmon_hook(&key, direction, pkt, pkt_len, tv, ret);
	}

	/* free our pkt */
	return pna_done(pkt);
}


/*
 * Module oriented code
 */
/* Initialization hook */
int pna_init(void)
{
	int i;
	int ret = 0;

	/* set up the flow table(s) */
	if ((ret = flowmon_init()) < 0)
		return ret;
	//init the domain mappings must be called after flowmon_init because of initialization of PNA proc entry
	pna_dtrie_init();

	if (rtmon_init() < 0) {
		pna_cleanup();
		return -1;
	}

	/* everything is set up, register the packet hook */
	pna_info("pna: capturing is available\n");

	return ret;
}

/* Destruction hook */
void pna_cleanup(void)
{
	rtmon_release();
	flowmon_cleanup();
	pna_info("pna: module is inactive\n");
}
