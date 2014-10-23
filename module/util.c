#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "util.h"

typedef int cpu_set_t;
#define CPU_ZERO(x)   *(x) = 0
#define CPU_SET(c, x) *(x) = (c)

/**************************************
 * The time difference in millisecond *
 **************************************/
double delta_time (struct timeval *now, struct timeval *before)
{
    time_t delta_seconds;
    time_t delta_microseconds;

    /* compute delta in second, 1/10's and 1/1000's second units */
    delta_seconds      = now->tv_sec  - before->tv_sec;
    delta_microseconds = now->tv_usec - before->tv_usec;

    if (delta_microseconds < 0) {
        /* manually carry a one from the seconds field */
        delta_microseconds += 1000000;    /* 1e6 */
        --delta_seconds;
    }
    return ((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

void print_stats(int type, void *pd, struct timeval *start, unsigned long long pkts, unsigned long long bytes)
{
    struct pcap_stat pcapStat;
    //pfring_stat pfringStat;

    struct timeval endTime;
    double deltaMillisec;
    static u_int64_t lastPkts = 0, lastBytes = 0;
    static struct timeval lastTime;
    unsigned long long diffPkts, diffBytes;
    unsigned long long recv = 0, drop = 0;


    if (start->tv_sec == 0) {
        gettimeofday(start, NULL);
    }

    gettimeofday(&endTime, NULL);
    deltaMillisec = delta_time(&endTime, start);

    if (type == PCAP && pcap_stats(pd, &pcapStat) >= 0) {
        recv = pcapStat.ps_recv;
        drop = pcapStat.ps_drop;
    }
//    else if (type == PFRING && pfring_stats(pd, &pfringStat) >= 0) {
//        recv = pfringStat.recv;
//        drop = pfringStat.drop;
//    }

    if (recv != 0 || drop != 0) {
        printf("=========================\n");
        printf("Absolute Stats: %llu pkts rcvd, %llu pkts dropped\n", recv, drop);
        printf("%llu pkts [%.1f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
                pkts, (pkts*1000.0)/deltaMillisec,
                bytes, (bytes*8.0)/(deltaMillisec*1000));

        if (lastTime.tv_sec > 0) {
            deltaMillisec = delta_time(&endTime, &lastTime);
            diffPkts = pkts - lastPkts;
            diffBytes = bytes - lastBytes;
            printf("=========================\n");
            printf("Interval Stats: %.1f s\n", deltaMillisec/1000);
            printf("%llu pkts [%.2f pkt/sec] - %llu bytes [%.2f Mbit/sec]\n",
                   diffPkts, (diffPkts*1000.0)/deltaMillisec,
                   diffBytes, (diffBytes*8.0)/(deltaMillisec*1000));
        }
    }
    else {
        printf("=========================\n");
        printf("No packets seen in this interval\n");
    }

    lastTime.tv_sec = endTime.tv_sec;
    lastTime.tv_usec = endTime.tv_usec;
    lastPkts = pkts;
    lastBytes = bytes;

    printf("=========================\n");
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
    u_int i, j;
    char *cp;

    cp = buf;
    if ((j = *ep >> 4) != 0)
        *cp++ = hex[j];
    else
        *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];

    for (i = 5; (int)--i >= 0;) {
        *cp++ = ':';
        if ((j = *ep >> 4) != 0)
            *cp++ = hex[j];
        else
            *cp++ = '0';

        *cp++ = hex[*ep++ & 0xf];
    }

    *cp = '\0';
    return (buf);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* _intoa(unsigned int addr, char* buf, u_short bufLen) {
    char *cp, *retStr;
    u_int byte;
    int n;

    cp = &buf[bufLen];
    *--cp = '\0';

    n = 4;
    do {
        byte = addr & 0xff;
        *--cp = byte % 10 + '0';
        byte /= 10;
        if (byte > 0) {
            *--cp = byte % 10 + '0';
            byte /= 10;
            if (byte > 0)
        *--cp = byte + '0';
        }
        *--cp = '.';
        addr >>= 8;
    } while (--n > 0);

    /* Convert the string to lowercase */
    retStr = (char*)(cp+1);

    return(retStr);
}

/* ************************************ */

char* intoa(unsigned int addr) {
    static char buf[sizeof "ff:ff:ff:ff:ff:ff:255.255.255.255"];

    return(_intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

inline char* in6toa(struct in6_addr addr6) {
    static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

    snprintf(buf, sizeof(buf), 
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2], 
             addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6], 
             addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10], 
             addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14], 
             addr6.s6_addr[15]);

    return(buf);
}

/* ****************************************************** */

char* proto2str(u_short proto) {
    static char protoName[8];

    switch(proto) {
    case IPPROTO_TCP:    return("TCP");
    case IPPROTO_UDP:    return("UDP");
    case IPPROTO_ICMP: return("ICMP");
    default:
        snprintf(protoName, sizeof(protoName), "%d", proto);
        return(protoName);
    }
}

/* *************************************** */

int32_t gmt2local(time_t t) {
    int dt, dir;
    struct tm *gmt, *loc;
    struct tm sgmt;

    if (t == 0)
        t = time(NULL);
    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);
    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
        (loc->tm_min - gmt->tm_min) * 60;

    /*
     * If the year or julian day is different, we span 00:00 GMT
     * and must add or subtract a day. Check the year first to
     * avoid problems when the julian day wraps.
     */
    dir = loc->tm_year - gmt->tm_year;
    if (dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;
    dt += dir * 24 * 60 * 60;

    return (dt);
}

/* *************************************** */
/* Bind this thread to a specific core */

int bind2core(u_int core_id) {
    cpu_set_t cpuset;
    int s;

    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    if ((s = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset)) != 0) {
        fprintf(stderr, "Error while binding to core %u: errno=%i\n", core_id, s);
        return(-1);
    } else {
        return(0);
    }
}
