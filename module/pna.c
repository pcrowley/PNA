/*
 *
 *
 */

#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>

#define ALARM_SLEEP     10
#define DEFAULT_SNAPLEN 256
pcap_t    *pd;
int verbose = 0;
struct pcap_stat pcapStats;

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/poll.h>
#include <time.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>         /* the L2 protocols */

#include "pna.h"
#include "util.h"

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define DEFAULT_DEVICE "eth1" /* "e1000" */

char pna_perfmon = 1;
char pna_flowmon = 0;
unsigned int pna_flow_entries = (1 << 23);

int pcap_set_cluster(pcap_t *ring, u_int clusterId);
int pcap_set_application_name(pcap_t *handle, char *name);
char* pfring_format_numbers(double val, char *buf, u_int buf_len, u_int8_t add_decimals);

/* ******************************** */

void sigproc(int sig) {
    static int called = 0;

    if (called) return; else called = 1;

    //print_stats(PCAP, pd, &startTime, numPkts, numBytes);
    pcap_close(pd);
    pna_cleanup();
    exit(0);
}

/* ******************************** */

void my_sigalarm(int sig) {
    print_stats(PCAP, pd, &startTime, numPkts, numBytes);
    alarm(ALARM_SLEEP);
    signal(SIGALRM, my_sigalarm);
}

/* ****************************************************** */

static int32_t thiszone;

void pkt_hook(u_char *_deviceId, const struct pcap_pkthdr *h, const u_char *p)
{
    if (numPkts == 0) gettimeofday(&startTime, NULL);

    pna_hook(h->len, h->ts, p);

    numPkts++;
    numBytes += h->len;
}

/* *************************************** */

void printHelp(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devpointer;

    printf("ppna\n(C) 2012 Michael J Schultz <mjschultz@gmail.com>\n");
    printf("-h                  [Print help]\n");
    printf("-i <device>         [Device name]\n");
    printf("-f <entries>    Number of flow table entries (default %u)\n", pna_flow_entries);
    printf("-v                  [Verbose]\n");

    if (pcap_findalldevs(&devpointer, errbuf) == 0) {
        int i = 0;
        
        printf("\nAvailable devices (-i):\n");
        while(devpointer) {
            printf(" %d. %s\n", i++, devpointer->name);
            devpointer = devpointer->next;
        }
    }
}

/* *************************************** */

int main(int argc, char* argv[]) {
    char *device = NULL, c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int promisc, snaplen = DEFAULT_SNAPLEN;;

    startTime.tv_sec = 0;
    thiszone = gmt2local(0);

    while((c = getopt(argc,argv,"hi:vf:")) != '?') {
        if (-1 == c) break;

        switch(c) {
        case 'h':
            printHelp();
            exit(0);
            break;
        case 'i':
            device = strdup(optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'f':
            pna_flowmon = 1;
            if (atoi(optarg) != 0)
                pna_flow_entries = atoi(optarg);
            break;
        }
    }

    if (device == NULL) {
        if ((device = pcap_lookupdev(errbuf)) == NULL) {
            printf("pcap_lookup: %s", errbuf);
            return(-1);
        }
    }
    printf("Capturing from %s\n", device);

    /* hardcode: promisc=1, to_ms=500 */
    promisc = 1;
    if ((pd = pcap_open_live(device, snaplen, 
                            promisc, 500, errbuf)) == NULL) {
        printf("pcap_open_live: %s\n", errbuf);
        return(-1);
    }

    pcap_set_application_name(pd, "ppna");

    signal(SIGINT, sigproc);

    if (verbose) {
        signal(SIGALRM, my_sigalarm);
        alarm(ALARM_SLEEP);
    }

    pna_init();

    pcap_loop(pd, -1, pkt_hook, NULL);
    pcap_close(pd);

    return(0);
}
