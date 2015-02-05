/**
 * user-space PNA
 * This is the driver for the PNA software, it is process-level parallel
 * per interface.
 */

#include <pcap.h>
#include <signal.h>
#include <sched.h>
#include <stdlib.h>

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

#define ALARM_SLEEP     10   // seconds between stat printouts
#define DEFAULT_SNAPLEN 256  // big enough for all the headers
#define PROMISC_MODE    1    // give us everything

pcap_t    *pd;
int verbose = 0;

static struct timeval startTime;
unsigned long long numPkts = 0, numBytes = 0;

#define ENV_PNA_LOGDIR "PNA_LOGDIR"
#define DEFAULT_LOG_DIR  "./logs"
char *log_dir;

char *listen_device = NULL;

/* PNA configuration parameters */
unsigned int pna_flow_entries = (1 << 23);
unsigned int pna_tables = 2;
unsigned int pna_bits = 16;

char pna_debug = false;
char pna_perfmon = 0;
char pna_flowmon = 1;
char pna_rtmon = false;

int pna_dtrie_init(void);
int pna_dtrie_deinit(void);
int pna_dtrie_build(char *networks_file);

/**
 * signal handler to terminate app
 */
void sigproc(int sig) {
    static int called = 0;

    if (called) {
        return;
    }
    else {
        called = 1;
    }

    pcap_close(pd);
    pna_dtrie_deinit();
    pna_cleanup();
    exit(0);
}

/**
 * periodic stats report for input/output numbers
 */
void stats_report(int sig) {
    print_stats(PCAP, pd, &startTime, numPkts, numBytes);
    alarm(ALARM_SLEEP);
    signal(SIGALRM, stats_report);
}

/**
 * This is the pcap callback hook that will grab the relevant info and pass
 * it on to the PNA software for handling
 */
void pkt_hook(u_char *device, const struct pcap_pkthdr *h, const u_char *p)
{
    // first packet we've seen, capture the time for stats
    if (numPkts == 0) {
        gettimeofday(&startTime, NULL);
    }

    // it appears to be an empty packet, skip it
    if (h->len == 0) {
        return;
    }

    // call the hook
    pna_hook(h->len, h->ts, p);

    // update stats
    numPkts++;
    numBytes += h->len;
}

/**
 * command line help
 */
void printHelp(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devpointer;

    printf("uPNA\n");
    printf("-h             Print help\n");
    printf("-i <device>    Device name\n");
    printf("-n <net_file>  File of networks to process\n");
    printf("-f <entries>   Number of flow table entries (default %u)\n",
           pna_flow_entries);
    printf("-v             Verbose mode\n");

    if (pcap_findalldevs(&devpointer, errbuf) == 0) {
        printf("\nAvailable devices (-i):\n");
        while (devpointer) {
            printf("- %s\n", devpointer->name);
            devpointer = devpointer->next;
        }
    }
}

/**
 * Main driver
 */
int main(int argc, char **argv) {
    char c;
    char errbuf[PCAP_ERRBUF_SIZE];
    int promisc;
    int ret;

    startTime.tv_sec = 0;

    /* load some environment variables */
    log_dir = getenv(ENV_PNA_LOGDIR);
    if (!log_dir) {
        log_dir = DEFAULT_LOG_DIR;
    }

    /* initialize needed pna components */
    pna_init();
    pna_dtrie_init();

    while ((c = getopt(argc, argv, "o:hi:n:vf:")) != '?') {
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            printHelp();
            exit(0);
            break;
        case 'o':
            log_dir = strdup(optarg);
            break;
        case 'i':
            listen_device = strdup(optarg);
            break;
        case 'n':
            ret = pna_dtrie_build(optarg);
            if (ret != 0) {
                exit(1);
            }
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

    if (listen_device == NULL) {
        // no device, find the default
        listen_device = pcap_lookupdev(errbuf);
        if (listen_device == NULL) {
            // no default? error out
            printf("pcap_lookup: %s", errbuf);
            return -1;
        }
    }
    printf("Capturing from %s\n", listen_device);

    // grab the pcap descriptor handle
    pd = pcap_open_live(
        listen_device, DEFAULT_SNAPLEN, PROMISC_MODE, 500, errbuf
    );
    if (pd == NULL) {
        printf("pcap_open_live: %s\n", errbuf);
        return -1;
    }

    // handle Ctrl-C kindly
    signal(SIGINT, sigproc);

    // if wanted, periodically print stat reports
    if (verbose) {
        signal(SIGALRM, stats_report);
        alarm(ALARM_SLEEP);
    }

    // ...and go!
    pcap_loop(pd, -1, pkt_hook, NULL);

    pcap_close(pd);
    return 0;
}
