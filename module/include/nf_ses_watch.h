
#ifndef _NF_SES_WATCH_H_
#define _NF_SES_WATCH_H_

/* configuration variables */
#define NCPUS              8
#define PNA_IF             "eth0"
//#define CFG_DEF_NET_PREFIX 0x80fc0000
#define CFG_DEF_NET_PREFIX 0xc0a80000
#define CFG_DEF_NET_MASK   0xffff0000

#include <asm/types.h>
#include <linux/if_ether.h>

/* log filename format, formatting by strftime(3)
 * %Y - full year (4 digits)
 * %m - month number [01-12]
 * %d - day number [01-31]
 * %H - hour [00-23]
 * %M - minute [00-59]
 */
#define TIMEFMT "%Y%m%d%H%M"
#define LOGROTATE  (60 * 60) /* new logfile every 60 minutes */
#define LOGSLEEP   10        /* time between reports (seconds) */
#define LOGDIR "logs"        /* directory in which to store log files */

/* if enabled (1), performance measure will be sent to syslog */
#define PERF_MEASURE 1

#define NF_NPROTO      2 /* number of supported protocols */
#define NF_SESSION_TCP 0
#define NF_SESSION_UDP 1

/* directional constants */
#define OUTBOUND    0
#define INBOUND     1
#define NDIRECTIONS 2

/* format of data shared through procfile */
#if 0
struct watch_data
{
	__u8 src_mac[ETH_ALEN];    /* 1 * 6 = 6 bytes */
	__u32 src_ip;              /* 4 * 1 = 4 bytes */
	__u32 dst_ip;              /* 4 * 1 = 4 bytes */
	__u32 nprts[NF_NPROTO];    /* 4 * 2 = 8 bytes */
	__u32 npackets[NF_NPROTO]; /* 4 * 2 = 8 bytes */
	__u32 nbytes[NF_NPROTO];   /* 4 * 2 = 8 bytes */
};
#endif /* 0 */

/* format of data shared through procfile */
typedef struct watch_port
{
    __u16 local_port;
    __u16 remote_port;
    __u32 npkts[NDIRECTIONS];
    __u32 nbytes[NDIRECTIONS];
    __u32 timestamp;
    __u8 first_dir;
	__u8 pad[3];
} watch_port_t;

typedef struct watch_data
{
	__u32 local_ip;
    __u32 remote_ip;
//    __u32 ntcp;
//    __u32 nudp;
//    unsigned char ports[1];
} watch_data_t;

/* procfs filename */
#define PROCDIR "nf_ses_watch"

/* configuration data */
#define PROCCFG "config"
#define PROC_LEN 8
struct cfg_xchange
{
	unsigned int type;
	unsigned int value;
};

/* configuration options */
#define NUM_CFG_PARAMS    13
#define CFG_THR_NDSTS     0
#define CFG_THR_NTCPPRTS  1
#define CFG_THR_NUDPPRTS  2
#define CFG_THR_NALLPRTS  3
#define CFG_THR_NTCPBYTES 4
#define CFG_THR_NUDPBYTES 5
#define CFG_THR_NALLBYTES 6
#define CFG_THR_NTCPPKTS  7
#define CFG_THR_NUDPPKTS  8
#define CFG_THR_NALLPKTS  9
#define CFG_THR_NSESS     10
#define CFG_NET_PREFIX    11
#define CFG_NET_MASK      12

/* Number of thresholds we can handle */
#define NTHRESHOLDS 11
#define THR_NDSTS   0
#define THR_NPRTS   1  /* 1 is TCP, 2 is UDP, 3 is ALL */
#define THR_NBYTES  4  /* 4 is TCP, 5 is UDP, 6 is ALL */
#define THR_NPKTS   7  /* 7 is TCP, 8 is UDP, 9 is ALL */
#define THR_NSESS   10 /* 7 is TCP, 8 is UDP, 9 is ALL */

#define THR_DEF_NDSTS  2000000000
#define THR_DEF_NSESS  2000000000
#define THR_DEF_NPRTS  2000000000
#define THR_DEF_NBYTES 2000000000
#define THR_DEF_NPKTS  2000000000

/* Control Message Information */
#define CONTROL_PORT 63112
#define MSG_LEN      8

#define NPR_BLOCK     1
#define NPR_UNBLOCK   2
#define NPR_CLEAR_ALL 3
#define NPR_WHITELIST 4

#endif /* _NF_SES_WATCH_H_ */
