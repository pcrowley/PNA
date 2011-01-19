#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/smp.h>
#include <linux/module.h>  
#include <linux/init.h>  
#include <linux/netfilter.h>
#include <linux/hash.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <net/ip.h>
#include <asm/atomic.h>

#include <linux/net.h>

#define ETH_HDR_LEN    14
#define INTERFRAME_GAP 8

static unsigned int debug = 0;

#if LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 18)
	typedef __u32 uintptr_t;
	#define NF_INET_PRE_ROUTING NF_IP_PRE_ROUTING
#endif

#include "../include/nf_ses_watch.h"

/* Maximum length of a string we will use */
#define MAX_STR 8

/*********/
/* NOTES */
/*********/
/* NSRC_ENTS, NDST_ENTS, and NPRT_ENTS must fit in kernel space */
/* (Linux 2.6.18 gives around 31 MB of space) */
/* Table requires:
 * 8*NPRT_ENTS + 24+(NPRT_ENTS/4)*NDST_ENTS + 12+(NDST_ENTS/8)*NSRC_ENTS
 * 8192 per table is ~25 MB
 */

/* for single core machine */
//#define NTABS     1
//#define NSRC_ENTS 8192 /* Number of entries in connection table */
//#define NSRC_BITS 13   /* bits needed to represent NSRC_ENTS */
//#define NDST_ENTS 8192 /* Number of entries in each session table */
//#define NDST_BITS 13   /* bits needed to represent NDST_ENTS */
//#define NPRT_ENTS 8192 /* Number of entries for src/dst ports*/
//#define NPRT_BITS 13   /* bits needed to represent NPRT_ENTS */

/* for 8 core machine */
#define NTABS     2
#define NSRC_ENTS 16384 /* Number of entries in connection table */
#define NSRC_BITS 14    /* bits needed to represent NSRC_ENTS */
#define NDST_ENTS 32768 /* Number of entries in each session table */
#define NDST_BITS 15    /* bits needed to represent NDST_ENTS */
#define NPRT_ENTS 65536  /* Number of entries for src/dst ports*/
#define NPRT_BITS 16    /* bits needed to represent NPRT_ENTS */

/* limits for probing on collision */
#define SRC_LIMIT 128
#define DST_LIMIT 128
#define PRT_LIMIT 128

#if PERF_MEASURE == 1
	/* for performance measures */
#    include <linux/jiffies.h>
    struct perf_struct
    {
        __u64 t_jiffies; /* 8 */
        struct timeval currtime; /* 8 */
        struct timeval prevtime; /* 8 */
        __u32 p_interval[NDIRECTIONS]; /* 8 */
        __u32 B_interval[NDIRECTIONS]; /* 8 */
        char pad[64-24-2*sizeof(struct timeval)];
    }; /* should total 64 bytes */
    struct perf_struct pstab[NTABS];
#    define MIN_PKT_BITS 512  /* 64 bytes * 8 bits per byte */
    /* taken from linux/jiffies.h in kernel v2.6.21 */
#    define time_after_eq64(a,b)    \
        (typecheck(__u64, a) && \
         typecheck(__u64, b) && \
         ((__s64)(a) - (__s64)(b) >= 0))
#endif /* PERF_MEASURE == 1 */

/* number of bits in a prt or dst entry index */
typedef u8 nf_bitmap;
#define BITMAP_BITS  (BITS_PER_BYTE*sizeof(nf_bitmap))

/* Level 3 entries (port tuple) */
/* 4 bytes */
struct nf_prt_entry {
    u16 local_port;
    u16 remote_port;
    u32 nbytes[NDIRECTIONS];
    u32 npkts[NDIRECTIONS];
	u32 timestamp;
	u32 info_bits;
};

/* Level 2 entries (remote IP tuple) */
/* 24+(NPRT_ENTS/4) bytes */
struct nf_rip_entry {
    u32 remote_ip;
	u32 info_bits;
    u16 nprts[NDIRECTIONS][NF_NPROTO];
    u32 nbytes[NDIRECTIONS][NF_NPROTO];
    u32 npkts[NDIRECTIONS][NF_NPROTO];
    nf_bitmap prts[NF_NPROTO][NPRT_ENTS/BITMAP_BITS];
};

/* Level 1 entries (local IP tuple) */
/* 12+(NDST_ENTS/8) bytes */
struct nf_lip_entry {
    u32 local_ip;
    u16 ndsts[NDIRECTIONS];
	u32 nsess[NDIRECTIONS];
    nf_bitmap dsts[NDST_ENTS/BITMAP_BITS];
};

union l4hdr {
    struct tcphdr tcp;
    struct udphdr udp;
};

/* function prototypes */
struct nf_lip_entry *do_lip_entry(u32, u32);
struct nf_rip_entry *do_rip_entry(struct nf_lip_entry *, u32, u32);
struct nf_prt_entry *do_prt_entry(struct nf_lip_entry *, 
    struct nf_rip_entry *, u16, u16, u16, u32, u32);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
unsigned int nf_ses_watch_hook(unsigned int, struct sk_buff*,
    const struct net_device *, const struct net_device *t,
    int (*)(struct sk_buff *));
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 18)
unsigned int nf_ses_watch_hook(unsigned int, struct sk_buff**,
    const struct net_device *, const struct net_device *t,
    int (*)(struct sk_buff *));
#endif
static int __init nf_ses_watch_init(void);
static void __exit nf_ses_watch_exit(void);

int monitor_read(char *, char **, off_t, int, int *, void *);
int config_read(char*, char**, off_t, int, int *, void *);
int config_write(struct file *, const char *, unsigned long, void *);

/****************/
/* Memory users */
/****************/
/* locks for tables */
spinlock_t tab_lock[NTABS];

/* netfilter hook operations */
struct nf_hook_ops nf_ops = {
	.hook = nf_ses_watch_hook,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

/* Table of connections */
/* XXX: with NTABS, these should be per processor protected */
struct nf_lip_entry lip_tab[NTABS][NSRC_ENTS];
struct nf_rip_entry rip_tab[NTABS][NDST_ENTS];
struct nf_prt_entry prt_tab[NTABS][NF_NPROTO][NPRT_ENTS];

/* threshold table */
/* XXX: this is effectively read-only, so not much contention */
u32 threshold[NTHRESHOLDS];

/* config vars for determining ingress/egress */
u32 net_prefix;
u32 net_mask;

/* Procfs pointers and index (8 bytes) */
/* XXX: only used in initialization */
static struct proc_dir_entry *proc_parent;

typedef struct smp_info
{
    int id;
    int local_idx;
    int remote_idx;
    int proto_idx;
    int port_idx;
} smp_info_t;
smp_info_t smp_info[NTABS];

atomic_t nlip[NTABS], nrip[NTABS], nprt[NTABS];
atomic_t excess_lip[NTABS], excess_rip[NTABS], excess_prt[NTABS];

/*
 * Actions to take are externally sourced
 */
#include "actions.c"

int table_map(int processor)
{
	return ((processor * NTABS) / NCPUS) % NTABS;
}

/*
 * Session table helper functions
 */

/* Find and set/update the level 1 table entry */
struct nf_lip_entry *do_lip_entry(u32 local_ip, u32 direction)
{
    struct nf_lip_entry *lip_entry;
    unsigned int i;
    unsigned int hash = hash_long(local_ip, NSRC_BITS);
	int lip_idx = table_map(smp_processor_id());

    /* loop through table until we find right entry */
//    for ( i = 0; i < NSRC_ENTS; i++ )
    for ( i = 0; i < SRC_LIMIT; i++ )
    {
        lip_entry = &lip_tab[lip_idx][hash];

        /* check if IP is a match */
        if (local_ip == lip_entry->local_ip)
        {
        	return lip_entry;
        }

        /* check if IP is clear */
        if (0 == lip_entry->local_ip)
        {
            /* set up entry and return it */
            lip_entry->local_ip = local_ip;
			atomic_inc(&nlip[lip_idx]);
            return lip_entry;
        }

        hash = (hash + 1) % NSRC_ENTS;
    }
   
	if (atomic_read(&excess_lip[lip_idx]) % 10000 == 0)
	{
		printk("miss: {0x%08x}\n", local_ip);
	}
	atomic_inc(&excess_lip[lip_idx]);
    return (struct nf_lip_entry *)NULL;
}

/* Find and set/update the level 2 table entry */
struct nf_rip_entry *do_rip_entry(struct nf_lip_entry *lip_entry,
								  u32 remote_ip, u32 direction)
{
    struct nf_rip_entry *rip_entry;
	nf_bitmap rip_bits;
    unsigned int i;
    unsigned int hash = lip_entry->local_ip ^ remote_ip;
	int rip_idx = table_map(smp_processor_id());
	hash = hash_long(hash, NDST_BITS);

    /* loop through table until we find right entry */
//    for ( i = 0; i < NDST_ENTS; i++ )
    for ( i = 0; i < DST_LIMIT; i++ )
    {
        rip_entry = &rip_tab[rip_idx][hash];
		rip_bits = lip_entry->dsts[hash/BITMAP_BITS];

        /* check for match */
        if ( remote_ip == rip_entry->remote_ip
			&& 0 != (rip_bits & (1 << hash % BITMAP_BITS)))
        {
			if ( 0 == (rip_entry->info_bits & (1 << direction)) )
			{
				/* we haven't seen this direction yet, add it */
				lip_entry->ndsts[direction]++;
				/* indicate that we've seen this direction */
				rip_entry->info_bits |= (1 << direction);
			}
            return rip_entry;
        }

        /* check for free spot */
        if ( 0 == rip_entry->remote_ip )
        {
            /* set index of src IP */
            lip_entry->dsts[hash/BITMAP_BITS] |= (1 << (hash % BITMAP_BITS));
            /* set all fields if a match */
            rip_entry->remote_ip = remote_ip;
            /* update the number of connections */
            lip_entry->ndsts[direction]++;
			/* indicate that we've seen this direction */
			rip_entry->info_bits |= (1 << direction);
            /* first time this remote IP was seen it was travelling ... */
			rip_entry->info_bits |= (1 << (direction + NDIRECTIONS));
			atomic_inc(&nrip[rip_idx]);
            return rip_entry;
        }

        /* move to next entry */
        hash = (hash + 1) % NDST_ENTS;
    }

	//if (trace)
	//{
	//	printk("miss: {0x%08x, 0x%08x}",
	//			lip_entry->local_ip, remote_ip);
	//}
	atomic_inc(&excess_rip[rip_idx]);
    return (struct nf_rip_entry *)NULL;
}

/* Find and set/update the level 3 table entry */
struct nf_prt_entry *do_prt_entry(struct nf_lip_entry *lip_entry,
                                  struct nf_rip_entry *rip_entry,
								  u16 proto, u16 local_port, u16 remote_port,
								  u32 length, u32 direction)
{
	struct timeval timeval;
    struct nf_prt_entry *prt_entry;
    nf_bitmap prt_bits;
    unsigned int i, hash;
    u32 ports;
	int prt_idx = table_map(smp_processor_id());

    /* hash on <(local_port << 16)|remote_port> */
    ports = rip_entry->remote_ip ^ ((remote_port << 16) | local_port);
    hash = hash_long(ports, NPRT_BITS);

    /* loop through table until we find right entry */
//    for ( i = 0; i < NPRT_ENTS; i++ )
    for ( i = 0; i < PRT_LIMIT; i++ )
    {
        prt_entry = &prt_tab[prt_idx][proto][hash];
        prt_bits = rip_entry->prts[proto][hash/BITMAP_BITS];

        /* check for match */
        if ( local_port == prt_entry->local_port
            && remote_port == prt_entry->remote_port
            && 0 != (prt_bits & (1 << hash%BITMAP_BITS)) )
        {
            rip_entry->nbytes[direction][proto] += length;
            rip_entry->npkts[direction][proto]++;
            prt_entry->nbytes[direction] += length;
            prt_entry->npkts[direction]++;

			if ( 0 == (prt_entry->info_bits & (1 << direction)) )
			{
				/* we haven't seen this direction yet, add it */
				rip_entry->nprts[direction][proto]++;
				/* indicate that we've seen this direction */
				prt_entry->info_bits |= (1 << direction);
			}
            return prt_entry;
        }

        /* check for free spot */
        if ( 0 == (prt_entry->local_port | prt_entry->remote_port) )
        {
            prt_entry->local_port = local_port;
            prt_entry->remote_port = remote_port;

            /* update all fields if a match */
            rip_entry->prts[proto][hash/BITMAP_BITS] |= (1 << hash%BITMAP_BITS);
            rip_entry->nbytes[direction][proto] += length;
            rip_entry->npkts[direction][proto]++;

			/* port specific information */
            prt_entry->nbytes[direction] += length;
            prt_entry->npkts[direction]++;
        	do_gettimeofday(&timeval);
			prt_entry->timestamp = timeval.tv_sec;

            rip_entry->nprts[direction][proto]++;
			/* indicate that we've seen this direction */
			prt_entry->info_bits |= (1 << direction);
            /* the first packet of a flow, mark the direction it came from */
			prt_entry->info_bits |= (1 << (direction + NDIRECTIONS));

			/* also update the lip_entry because this is a new session */
			lip_entry->nsess[direction]++;
			atomic_inc(&nprt[prt_idx]);
            return prt_entry;
        }

        /* move to next entry */
        hash = (hash + 1) % NPRT_ENTS;
    }

	//if (trace)
	//{
	//	printk("miss: {0x%08x, 0x%08x, 0x%04x:0x%04x}",
	//			lip_entry->local_ip, rip_entry->remote_ip, local_port,
	//			remote_port);
	//}
	atomic_inc(&excess_prt[prt_idx]);
    return (struct nf_prt_entry *)NULL;
}

/*
 * Netfilter hook/setup/takedown functions
 */

/* Netfilter hook */
unsigned int nf_ses_watch_hook(unsigned int hooknum, 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
                               struct sk_buff *skb,
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 18)
                               struct sk_buff **skb,
#endif
                               const struct net_device *in,
                               const struct net_device *out,
                               int (*okfn)(struct sk_buff *))
{
    unsigned int ret;
    struct ethhdr *l2hdr;
    struct iphdr *l3hdr;
    union l4hdr *l4hdr;
    unsigned int iphdr_len;
    struct nf_lip_entry *lip_entry;
    struct nf_rip_entry *rip_entry;
    struct nf_prt_entry *prt_entry;
	u32 direction, temp;
	u32 local_ip, remote_ip;
    u16 local_port, remote_port, proto, pkt_len;
	int tab_id = table_map(smp_processor_id());
#if PERF_MEASURE == 1
    struct perf_struct *ps = &(pstab[tab_id]);
#endif /* PERF_MEASURE */

    /* We have one function, snoop and log packets, Linux can ignore them */
    ret = NF_DROP;

	/* We only accept if the `in` device is not one we care about */
	if ( 0 != strncmp(in->name, PNA_IF, IFNAMSIZ))
	{
		return NF_ACCEPT;
	}

    /* grab the packet headers */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
    l2hdr = (struct ethhdr *)skb_mac_header(skb);
    l3hdr = (struct iphdr *)skb_network_header(skb);
	pkt_len = ntohs(l3hdr->tot_len);

    /* (*skb)->h has not been set up yet. So we hack. */
    iphdr_len = l3hdr->ihl * sizeof(int);
    l4hdr = (union l4hdr *)((uintptr_t)(skb->data) + iphdr_len);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2, 6, 18)
    l2hdr = (struct ethhdr *)(*skb)->mac.raw;
    l3hdr = (struct iphdr *)(*skb)->nh.raw;
	pkt_len = ntohs(l3hdr->tot_len);

    /* (*skb)->h has not been set up yet. So we hack. */
    iphdr_len = l3hdr->ihl * sizeof(int);
    l4hdr = (union l4hdr *)((uintptr_t)((*skb)->data) + iphdr_len);
#else
	#error "Untested kernel version"
#endif

    /* grab transport specific information */
    switch (l3hdr->protocol)
    {
    case SOL_TCP:
        proto = NF_SESSION_TCP;
        local_port = ntohs(l4hdr->tcp.source);
        remote_port = ntohs(l4hdr->tcp.dest);
        break;
    case SOL_UDP:
        proto = NF_SESSION_UDP;
        local_port = ntohs(l4hdr->udp.source);
        remote_port = ntohs(l4hdr->udp.dest);
        break;
    default:
       /* If we don't recognize it, let Linux handle it */
       return NF_DROP;
    }

	/* Determine the nature of this packet (ingress or egress) */
	/* assume that we have a local packet first */
	local_ip = ntohl(l3hdr->saddr);

	/* check that it is local */
	temp = local_ip & net_mask;
	if ( temp == net_prefix )
	{
		/* saddr is local */
		// local_ip, local_port, remote_port are set
		remote_ip = ntohl(l3hdr->daddr);
		direction = OUTBOUND;
	}
	else
	{
		/* assume daddr is local */
		remote_ip = local_ip;
		local_ip = ntohl(l3hdr->daddr);

		temp = local_port;
		local_port = remote_port;
		remote_port = temp;
		direction = INBOUND;
	}

#if PERF_MEASURE == 1
    /**********************************
     *   PERFORMANCE EVALUTION CODE   *
     **********************************/
    /* time_after_eq64(a,b) returns true if time a >= time b. */
    if ( time_after_eq64(get_jiffies_64(), ps->t_jiffies) )
    {
        __u32 t_interval;
        __u32 kpps_in, Mbps_in, avg_in;
        __u32 kpps_out, Mbps_out, avg_out;

        /* get sampling interval time */
        do_gettimeofday(&ps->currtime);
        t_interval = ps->currtime.tv_sec - ps->prevtime.tv_sec;
    /* update for next round */
        ps->prevtime = ps->currtime;

        /* calculate the numbers */
        kpps_in = ps->p_interval[INBOUND] / 1000 / t_interval;
		/* 125000 Mb = (1000 MB/KB * 1000 KB/B) / 8 bits/B */
        Mbps_in = ps->B_interval[INBOUND] / 125000 / t_interval;
		if (ps->p_interval[INBOUND] != 0)
		{
			avg_in = (ps->B_interval[INBOUND]/ps->p_interval[INBOUND])-INTERFRAME_GAP;
		}
		else
		{
			avg_in = 0;
		}

        kpps_out = ps->p_interval[OUTBOUND] / 1000 / t_interval;
		/* 125000 Mb = (1000 MB/KB * 1000 KB/B) / 8 bits/B */
        Mbps_out = ps->B_interval[OUTBOUND] / 125000 / t_interval;
		if (ps->p_interval[OUTBOUND] != 0)
		{
			avg_out = (ps->B_interval[OUTBOUND]/ps->p_interval[OUTBOUND])-INTERFRAME_GAP;
		}
		else
		{
			avg_out = 0;
		}

        /* report the numbers */
        if (kpps_in + kpps_out > 0)
        {
			printk("pna_mod: hit in:{kpps:%u,Mbps:%u,avg:%u} out:{kpps:%u,Mbps:%u,avg:%u}\n",
					kpps_in, Mbps_in, avg_in, kpps_out, Mbps_out, avg_out);
			printk("on processor %d\n", smp_processor_id());
        }

        /* set updated counters */
        ps->p_interval[INBOUND] = 0;
        ps->B_interval[INBOUND] = 0;
        ps->p_interval[OUTBOUND] = 0;
        ps->B_interval[OUTBOUND] = 0;
        ps->t_jiffies = msecs_to_jiffies(LOGSLEEP*MSEC_PER_SEC);
        ps->t_jiffies += get_jiffies_64();
    }

    /* increment packets seen in this interval */
    ps->p_interval[direction]++;
    ps->B_interval[direction] += pkt_len + ETH_HDR_LEN + INTERFRAME_GAP;
    /**********************************
     * END PERFORMANCE EVALUTION CODE *
     **********************************/
#endif /* PERF_MEASURE == 1 */

    /* We'll let Linux handle ARP packets from monitored ports */
    if ((ETH_P_ARP == htons(l2hdr->h_proto)))
    {
        return NF_DROP;
    }

	/* make sure the local IP is one of interest */
	temp = local_ip & net_mask;
	if ( temp != net_prefix )
	{
		/* don't monitor this packet, but don't let Linux see it either */
		return NF_DROP;
	}

	/* lock the table */
	spin_lock(&tab_lock[tab_id]);

    /* find the entry beginning this connection*/
    lip_entry = do_lip_entry(local_ip, direction);
    if ( NULL == lip_entry )
    {
		if (debug) printk("detected full source table\n");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
    }
    else if ( lip_entry->ndsts[OUTBOUND] >= threshold[THR_NDSTS] )
	{
		/* host is trying to connect to too many destinations, ignore */
		session_action(NPR_BLOCK, local_ip, "too many connections");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
	}

    /* find the entry completing this connection */
    rip_entry = do_rip_entry(lip_entry, remote_ip, direction);
    if ( NULL == rip_entry )
    {
		/* destination table is *FULL,* can't do anything */
		if (debug) printk("detected full destination table\n");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
    }
    else if ( rip_entry->nprts[OUTBOUND][proto] >= threshold[THR_NPRTS+proto] )
	{
		/* host is creating too many unique sessions, ignore */
		session_action(NPR_BLOCK, local_ip, "too many ports");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
	}
	else if ( rip_entry->nbytes[OUTBOUND][proto] >= threshold[THR_NBYTES+proto] )
	{
		/* host has surpassed a huge amount of protocol bandwidth, ignore */
		session_action(NPR_BLOCK, local_ip, "too many bytes");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
	}
	else if ( rip_entry->npkts[OUTBOUND][proto] >= threshold[THR_NPKTS+proto] )
	{
		/* host has surpassed a huge amount of protocol traffic, ignore */
		session_action(NPR_BLOCK, local_ip, "too many packets");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
	}
	/* XXX: might also want to do ALL thresholds */

    /* update the session entry */
	prt_entry = do_prt_entry(lip_entry, rip_entry, proto, local_port,
			                 remote_port, pkt_len, direction);
    if ( NULL == prt_entry )
    {
		if (debug) printk("detected full port table\n");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
    }
	else if ( lip_entry->nsess[OUTBOUND] >= threshold[THR_NSESS] )
	{
		/* host is trying to connect to too many destinations, ignore */
		session_action(NPR_BLOCK, local_ip, "too many sessions");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
	}
	else if ( lip_entry->nsess[INBOUND] >= threshold[THR_NSESS] )
	{
		/* host is trying to connect to too many destinations, ignore */
		session_action(NPR_WHITELIST, local_ip, "external scan");
		spin_unlock(&tab_lock[tab_id]);
        return ret;
	}

	spin_unlock(&tab_lock[tab_id]);
    return ret;
}

/* Initialization hook */
static int __init nf_ses_watch_init(void)
{
    struct perf_struct *ps;
    static struct proc_dir_entry *proc_node;
    int i;
    char i_str[MAX_STR];

	/* create table locks */
	for (i = 0; i < NTABS; i++)
	{
		tab_lock[i] = SPIN_LOCK_UNLOCKED;
	}

	for (i = 0; i < NTABS; i++)
	{
		spin_lock(&tab_lock[i]);
	}
    /* make sure table is clean */
    memset((void *)lip_tab, 0, NTABS * sizeof(struct nf_lip_entry) * NSRC_ENTS);
    memset((void *)rip_tab, 0, NTABS * sizeof(struct nf_rip_entry) * NDST_ENTS);
    memset((void *)prt_tab, 0, NTABS * sizeof(struct nf_prt_entry) * NPRT_ENTS);
	for (i = 0; i < NTABS; i++)
	{
		spin_unlock(&tab_lock[i]);
	}

	/* setup some default thresholds */
	threshold[THR_NDSTS] = THR_DEF_NDSTS;
	threshold[THR_NSESS] = THR_DEF_NSESS;
	threshold[THR_NPRTS+NF_SESSION_TCP]  = THR_DEF_NPRTS;
	threshold[THR_NPRTS+NF_SESSION_UDP]  = THR_DEF_NPRTS;
	threshold[THR_NPRTS+NF_NPROTO]       = THR_DEF_NPRTS;
	threshold[THR_NBYTES+NF_SESSION_TCP] = THR_DEF_NBYTES;
	threshold[THR_NBYTES+NF_SESSION_UDP] = THR_DEF_NBYTES;
	threshold[THR_NBYTES+NF_NPROTO]      = THR_DEF_NBYTES;
	threshold[THR_NPKTS+NF_SESSION_TCP]  = THR_DEF_NPKTS;
	threshold[THR_NPKTS+NF_SESSION_UDP]  = THR_DEF_NPKTS;
	threshold[THR_NPKTS+NF_NPROTO]       = THR_DEF_NPKTS;

	/* set default netmask and prefix */
	net_prefix = CFG_DEF_NET_PREFIX;
	net_mask = CFG_DEF_NET_MASK;

    /* netfilter ops setup */
    //nf_ops.list.next = nf_ops.list.prev = NULL;
    //nf_ops.hook = (nf_hookfn *)nf_ses_watch_hook;
    //nf_ops.pf = PF_INET; /* IP protocol family */
    //nf_ops.hooknum = NF_INET_PRE_ROUTING;
    nf_register_hook(&nf_ops);

#if PERF_MEASURE == 1
    for (i = 0; i < NTABS; i++)
    {
        ps = &(pstab[i]);
        /* set performance counters to initial values */
        ps->t_jiffies = msecs_to_jiffies(LOGSLEEP * MSEC_PER_SEC);
        ps->t_jiffies += get_jiffies_64();
        do_gettimeofday(&ps->prevtime);
    }
#endif /* PERF_MEASURE */

    /* setup the proc filesystem */
    proc_parent = proc_mkdir(PROCDIR, NULL);

    /* setup procfs handler(s) */
    for (i = 0; i < NTABS; i++)
    {
        /* setup smp structure */
        smp_info[i].id = i;
        smp_info[i].local_idx = 0;
        smp_info[i].remote_idx = 0;

        snprintf(i_str, MAX_STR, "%d", i);
        proc_node = create_proc_entry(i_str, 0644, proc_parent);
        if (NULL == proc_node)
        {
            remove_proc_entry(i_str, proc_parent);
            printk("Could not initialize /proc/%s/%d\n", PROCDIR, i);
            return -ENOMEM;
        }
//        proc_node->read_proc = proc_read[i];
        proc_node->read_proc = monitor_read;
        proc_node->data = &smp_info[i];
        proc_node->mode = S_IFREG | S_IRUGO;
        proc_node->uid = 0;
        proc_node->gid = 0;
        proc_node->size = 37;
    }

	proc_node = create_proc_entry(PROCCFG, 0664, proc_parent);
	if (NULL == proc_node)
	{
		remove_proc_entry(PROCCFG, proc_parent);
		printk("Could not initialize /proc/%s/%s\n", PROCDIR, PROCCFG);
		return -ENOMEM;
	}
	proc_node->read_proc = config_read;
	proc_node->write_proc = config_write;
	proc_node->mode = S_IFREG | S_IRUGO | S_IWUSR | S_IWGRP;
	proc_node->uid = 0;
	proc_node->gid = 0;
	proc_node->size = 37;

    ip_promisc(1);

	printk("pna module initialized with %d processors\n", NCPUS);
    return 0;
}

/* Destruction hook */
static void __exit nf_ses_watch_exit(void)
{
    int i;
    char i_str[MAX_STR];

    ip_promisc(0);
    nf_unregister_hook(&nf_ops);
    for (i = 0; i < NTABS; i++)
    {
        snprintf(i_str, MAX_STR, "%d", i);
        remove_proc_entry(i_str, proc_parent);
    }
    remove_proc_entry(PROCCFG, proc_parent);
    remove_proc_entry(PROCDIR, NULL);
}

/* source some external files */
/*XXX: bad form, but it works... */

#include "config.c"
#include "monitor.c"

/*
 * Module setup/meta/takedown handlers
 */

module_init(nf_ses_watch_init);
module_exit(nf_ses_watch_exit);

MODULE_LICENSE("GPL");
