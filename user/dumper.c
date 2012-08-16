/**
 * Generic pcap dumper routine, just symlink to a filter name it it will
 * create the files as needed.
 *
 * - This uses the standard open(), read(), close() system calls.
 * - An mmap() option may become available in the future, but will require
 *   a separate signalling mechanism.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <dirent.h>
#include <pcap.h>
#include <fcntl.h>
#include <time.h>

#include "pna.h"

#define PKTS_PER_TRACE 100
#define DEFAULT_LOG_DIR "./logs"
#define OUT_FMT "%s/%%Y%%m%%d%%H%%M%%S-%s.pcap"
#define BUFSZ 2048

int verbose;
char *prog_name;

char *log_dir = DEFAULT_LOG_DIR;
char outname[MAXNAMLEN];
pcap_t *pcap;

void monitor_init(void)
{
    time_t start;
    struct tm *start_gmt;
    char *name;

    /* create a fake pcap device for the dumper */
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    name = basename(prog_name);
    snprintf(outname, MAXNAMLEN, OUT_FMT, log_dir, name);
}

void monitor_release(void)
{
    /* close pcap object */
    pcap_close(pcap);
}

void monitor_hook(struct session_key *key, int direction,
                  struct pna_packet *pkt, unsigned long *info)
{
    static int npkts = 0;
    static pcap_dumper_t *dumper;

    time_t start;
    struct tm *start_gmt;
    struct pcap_pkthdr hdr;
    char outfile[MAXNAMLEN];

    /* open up a dumper if needed */
    if (npkts == 0) {
        start = time(NULL);
        start_gmt = gmtime((time_t *)&start);
        strftime(outfile, MAXNAMLEN, outname, start_gmt);
        dumper = pcap_dump_open(pcap, outfile);
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
    }
    else {
        pcap_dump_flush(dumper);
    }
}

/* ----------------------------- */

void usage(void)
{
    printf("usage: %s [-v] [-d <logdir>]\n", prog_name);
    printf("\t-v\tverbose mode (show quantities and time information)\n");
    printf("\t-d <logdir>\tsave logs to <logdir> (default: %s)\n",
                                    DEFAULT_LOG_DIR);
    exit(1);
}

/**
 * user_message will start this program with the name of the proc-file as
 * the command line argument.
 */
int main(int argc, char **argv)
{
    int pd;
    char *procfile;
    char opt;
    ssize_t nbytes;
    char buf[BUFSZ];
    struct pna_packet *pkt;

    prog_name = argv[0];

    /* process any arguments */
    while ((opt = getopt(argc, argv, "e:d:v")) != -1) {
        switch (opt) {
            case 'd':
                log_dir = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'e':
                break;
            case '?':
            default:
                usage();
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1) {
        usage();
    }

    procfile = argv[0];

    if (verbose) {
        printf("running %s with %s\n", prog_name, procfile);
    }

    /* call the monitor initialization routine */
    monitor_init();

    /* open the procfile for reading */
    pd = open(procfile, O_RDONLY);
    if (-1 == pd) {
        perror("procfile open failed");
        return -1;
    }

    /* as long as the procfile doesn't send EOF, keep reading */
    while (0 < (nbytes = read(pd, buf, BUFSZ))) {
        pkt = (struct pna_packet *)buf;

        /* make sure the buffer holds all the data we expect */
        printf("got %d bytes\n", nbytes);
        fflush(stdout);
        if (nbytes != pkt->length) {
            /* it does not, ignore this packet */
            fprintf(stderr, "did not capture entire packet\n");
            continue;
        }

        /* call the monitor hook function with params */
        monitor_hook(&pkt->key, pkt->direction, pkt, pkt->info);
    }

    /* close the procfile when done */
    close(pd);

    /* call any monitor release routines */
    monitor_release();
}

