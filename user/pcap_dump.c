#include <stdio.h>
#include <libgen.h>
#include <time.h>
#include <pcap.h>

#include "pna.h"

#define PKTS_PER_TRACE 100
#define OUT_FMT "%s/%%Y%%m%%d%%H%%M%%S-%s.pcap"
void monitor_init(void);
void monitor_release(void);
void monitor_hook(struct session_key *, int, struct pna_packet *);

char outname[MAX_STR];
pcap_t *pcap;

/**
 * PNA monitor configuration.
 * You need to define your .init, .release, and .hook callbacks.
 * pna_main will fill in the verbose, prog_name, and log_dir variables
 * (among others).
 */
struct pna_config cfg = {
    .init = monitor_init,
    .release = monitor_release,
    .hook = monitor_hook,
};

/**
 * Initialization routines for your monitor.
 * Allocate any global resources or initial values here.
 */
void monitor_init(void)
{
    char *name;

    /* create a fake pcap device for the dumper */
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    name = basename(cfg.prog_name);
    snprintf(outname, MAX_STR, OUT_FMT, cfg.log_dir, name);
}

/**
 * Release routines for your monitor.
 * Free up or write out any remaining data you may have, the program is
 * exiting.
 */
void monitor_release(void)
{
    /* close pcap object */
    pcap_close(pcap);
}

/**
 * Per-packet hook routine for your monitor.
 * This is the main workhorse. It should be efficient. The parameters are
 * designed to help you access simple data (local/remote ip/port, protocol
 * info, pointers to specific headers, etc.).
 * @param *key contains local+remote ip and port, l3 and l4 protocol
 * @param direction specifies if packet was inbound or outbound
 * @param *pkt wrapper the actual packet data, has length and packet data
 */
void monitor_hook(struct session_key *key, int direction,
                  struct pna_packet *pkt)
{
    static int npkts = 0;
    static pcap_dumper_t *dumper;

    time_t start;
    struct tm *start_gmt;
    struct pcap_pkthdr hdr;
    char outfile[MAX_STR];

    /* open up a dumper if needed */
    if (npkts == 0) {
        start = time(NULL);
        start_gmt = gmtime((time_t *)&start);
        strftime(outfile, MAX_STR, outname, start_gmt);
        dumper = pcap_dump_open(pcap, outfile);

        printf("dumper open\n");
        fflush(stdout);
    }

    /* fill out header info and write out packet to pcap file */
    hdr.ts = pkt->ts;
    hdr.len = pkt->real_length;
    hdr.caplen = pkt->length - sizeof(*pkt);
    pcap_dump((u_char *)dumper, &hdr, (u_char *)pkt->data);
    npkts += 1;

    /* enough packets in this trace, create a new one */
    if (PKTS_PER_TRACE == npkts) {
        npkts = 0;
        pcap_dump_close(dumper);
        printf("dumper close\n");
        fflush(stdout);
    }
    else {
        pcap_dump_flush(dumper);
        printf("dumper flush\n");
        fflush(stdout);
    }
}

/**
 * Main routine.
 * This is executed when the PNA detects a matching filter (e.g., if this
 * is an 'http' monitor, an 'http' filter must be registered with the PNA:
 * see service/filter for more details on registering a filter).
 * The parameters that are handed to this program are defined by the pna,
 * so you shouldn't have to deviate too much from this stub.
 */
int main(int argc, char **argv)
{
    pna_main(argc, argv, &cfg);
    pna_monitor(&cfg);
}
