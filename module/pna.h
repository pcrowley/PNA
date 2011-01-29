#ifndef __PNA_H
#define __PNA_H

/* /proc directory PNA tables will be stored in */
#define PNA_PROCDIR  "pna"

/* name format of PNA table files */
#define PNA_PROCFILE "table%d"
#define PNA_MAX_STR  16

/* shared kernel/user space data for alert system */
#ifndef __KERNEL__
char *pna_alert_types[] = {
	"none",
	"connections",
	"sessions",
	"ports",
	"bytes",
	"packets",
};
char *pna_alert_protocols[] = { "none", "tcp", "udp", "both", };
char *pna_alert_directions[] = { "none", "in", "out", "bi", };
#endif /* __KERNEL__ */

/* XXX: bad practice, but it gets the job done */
/* could be trouble if Linux decides to use more netlink links */
#define NETLINK_PNA 31

/* PNA alert commands */
#define PNA_ALERT_CMD_REGISTER   0x0001
#define PNA_ALERT_CMD_UNREGISTER 0x0002
#define PNA_ALERT_CMD_WARN       0x0003

/* PNA alert warning reasons OR'd together: (type | proto | dir) */ 
#define PNA_ALERT_TYPE_CONNECTIONS 0x0001
#define PNA_ALERT_TYPE_SESSIONS    0x0002
#define PNA_ALERT_TYPE_PORTS       0x0003
#define PNA_ALERT_TYPE_BYTES       0x0004
#define PNA_ALERT_TYPE_PACKETS     0x0005
#define PNA_ALERT_TYPE_MASK        0x00ff
#define PNA_ALERT_TYPE_SHIFT       0

#define PNA_ALERT_PROTO_TCP        0x0100
#define PNA_ALERT_PROTO_UDP        0x0200
#define PNA_ALERT_PROTO_ALL ( PNA_ALERT_PROTO_TCP | PNA_ALERT_PROTO_UDP )
#define PNA_ALERT_PROTO_MASK       0x0f00
#define PNA_ALERT_PROTO_SHIFT      8

#define PNA_ALERT_DIR_IN           0x1000
#define PNA_ALERT_DIR_OUT          0x2000
#define PNA_ALERT_DIR_INOUT ( PNA_ALERT_DIR_IN | PNA_ALERT_DIR_OUT )
#define PNA_ALERT_DIR_MASK         0x3000
#define PNA_ALERT_DIR_SHIFT        12

struct pna_alert_msg {
	short command;
	short reason;
	unsigned int value;
};
#define PNA_ALERT_MSG_SZ (sizeof(struct pna_alert_msg))

/* various constants */
#define PNA_DIRECTIONS 2 /* out and in */
# define PNA_DIR_OUTBOUND 0
# define PNA_DIR_INBOUND  1

#define PNA_PROTOS  2 /* tcp and udp */
# define PNA_PROTO_TCP 0
# define PNA_PROTO_UDP 1

/* settings/structures for storing <src,dst,port> entries */
#define PNA_LIP_ENTRIES  1024
#define PNA_LIP_BITS     10
#define PNA_RIP_ENTRIES  1024
#define PNA_RIP_BITS     10
#define PNA_PORT_ENTRIES 1024
#define PNA_PORT_BITS    10

/* some typedefs */
typedef unsigned char uchar;
#define PNA_BITS_PER_BYTE 8

/* number of bits in a prt or dst entry index */
typedef uchar pna_bitmap;
#define BITMAP_BITS  (PNA_BITS_PER_BYTE*sizeof(pna_bitmap))

struct lip_entry {
    uint local_ip;
    ushort ndsts[PNA_DIRECTIONS];
    uint nsess[PNA_DIRECTIONS];
    pna_bitmap dsts[PNA_LIP_ENTRIES/BITMAP_BITS];
};
#define PNA_SZ_LIP_ENTRIES (PNA_LIP_ENTRIES * sizeof(struct lip_entry))
struct rip_entry {
    uint remote_ip;
    uint info_bits;
    ushort nprts[PNA_DIRECTIONS][PNA_PROTOS];
    uint nbytes[PNA_DIRECTIONS][PNA_PROTOS];
    uint npkts[PNA_DIRECTIONS][PNA_PROTOS];
    pna_bitmap prts[PNA_PROTOS][PNA_PORT_ENTRIES/BITMAP_BITS];
};
#define PNA_SZ_RIP_ENTRIES (PNA_RIP_ENTRIES * sizeof(struct rip_entry))
struct port_entry {
    ushort local_port;
    ushort remote_port;
    uint nbytes[PNA_DIRECTIONS];
    uint npkts[PNA_DIRECTIONS];
    uint timestamp;
    uint info_bits;
};
#define PNA_SZ_PORT_ENTRIES (PNA_PORT_ENTRIES * sizeof(struct port_entry))

#define PNA_TABLE_SIZE \
	(PNA_SZ_LIP_ENTRIES + PNA_SZ_RIP_ENTRIES + 2*PNA_SZ_PORT_ENTRIES)

/* table meta-information */
#ifdef __KERNEL__
struct utab_info {
	void *table_base;
	char table_name[PNA_MAX_STR];
    struct lip_entry *lips;
    struct rip_entry *rips;
    struct port_entry *ports[PNA_PROTOS];

	struct mutex read_mutex;
	int  table_dirty;
	int  smp_id;
	char iface[PNA_MAX_STR];
    uint nlips;
    uint nlips_missed;
    uint nrips;
    uint nrips_missed;
    uint nports;
    uint nports_missed;
};
#endif /* __KERNEL__ */

/* some prototypes */
#ifdef __KERNEL__
int pna_alert_warn(int reason, int value);
int pna_alert_init(void);
void pna_alert_cleanup(void);
unsigned int pna_packet_hook(unsigned int hooknum, 
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *));
#endif /* __KERNEL__ */

#endif /* __PNA_H */
