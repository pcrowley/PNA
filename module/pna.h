#ifndef __PNA_H
#define __PNA_H

/* /proc directory PNA tables will be stored in */
#define PNA_PROCDIR  "pna"

/* name format of PNA table files */
#define PNA_PROCFILE "table%d"
#define PNA_MAX_STR  16

/* messages from kernel to action handler */
#define PNA_MSG_BLOCK     0x01
#define PNA_MSG_WHITELIST 0x02

/* various constants */
#define DIRECTIONS 2 /* out and in */
# define PNA_DIR_OUTBOUND 0
# define PNA_DIR_INBOUND  1

#define PNA_PROTOS  2 /* tcp and udp */
# define PNA_PROTO_TCP 0
# define PNA_PROTO_UDP 1

/* settings/structures for storing <src,dst,port> entries */
#define PNA_LIP_ENTRIES  4096
#define PNA_LIP_BITS     12
#define PNA_RIP_ENTRIES  4096
#define PNA_RIP_BITS     12
#define PNA_PORT_ENTRIES 4096
#define PNA_PORT_BITS    12

/* number of bits in a prt or dst entry index */
typedef u8 nf_bitmap;
#define BITMAP_BITS  (BITS_PER_BYTE*sizeof(nf_bitmap))

struct lip_entry {
    uint local_ip;
    ushort ndsts[DIRECTIONS];
    uint nsess[DIRECTIONS];
    nf_bitmap dsts[PNA_LIP_ENTRIES/BITMAP_BITS];
};
struct rip_entry {
    uint remote_ip;
    uint info_bits;
    ushort nprts[DIRECTIONS][PNA_PROTOS];
    uint nbytes[DIRECTIONS][PNA_PROTOS];
    uint npkts[DIRECTIONS][PNA_PROTOS];
    nf_bitmap prts[PNA_PROTOS][PNA_PORT_ENTRIES/BITMAP_BITS];
};
struct port_entry {
    ushort local_port;
    ushort remote_port;
    uint nbytes[DIRECTIONS];
    uint npkts[DIRECTIONS];
    uint timestamp;
    uint info_bits;
};

#define PNA_TABLE_SIZE (PNA_LIP_ENTRIES+PNA_RIP_ENTRIES+PNA_PORT_ENTRIES)

/* table meta-information */
struct utab_info {
	void *table_base;
	int  table_dirty;
	int  smp_id;
	char iface[PNA_MAX_STR];
    struct lip_entry *lips;
    struct rip_entry *rips;
    struct port_entry *ports[PNA_PROTOS];
    uint nlips;
    uint nlips_missed;
    uint nrips;
    uint nrips_missed;
    uint nports;
    uint nports_missed;
};

/* some prototypes */
int session_action(int type, int value, char *message);

#endif /* __PNA_H */
