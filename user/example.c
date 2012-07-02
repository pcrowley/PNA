/**
 * Simple example program that interacts with the pna_example real-time
 * monitor.
 * - The monitor samples 1 out of every 100 packets
 * - This user-space program should then recieve 1 out of every 100 packets
 *   and write it to a pcap formatted file.
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

char *prog_name;
int verbose;

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
    int npkts;
    char opt;
    char *procfile;
    ssize_t nbytes;
    time_t start;
    struct tm *start_gmt;
    char buf[BUFSZ];
    char outname[MAXNAMLEN];
    char outfile[MAXNAMLEN];
    pcap_t *pcap;
    pcap_dumper_t *dumper;
    struct pcap_pkthdr hdr;
    struct pna_packet *pkt;
    char *name;
    char *log_dir = DEFAULT_LOG_DIR;

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

    /* open the procfile for reading */
    pd = open(procfile, O_RDONLY);
    if (-1 == pd) {
        perror("procfile open failed");
        return -1;
    }

    /* create a fake pcap device for the dumper */
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    name = basename(prog_name);
    snprintf(outname, MAXNAMLEN, OUT_FMT, log_dir, name);

    /* prep the filename for output */
    start = time(NULL);
    start_gmt = gmtime((time_t *)&start);
    strftime(outfile, MAXNAMLEN, outname, start_gmt);
    dumper = pcap_dump_open(pcap, outfile);

    if (verbose) {
        printf("procdesc = %d ; pcap@%p ; dumper@%p\n", pd, pcap, dumper);
        printf("name='%s' ; file='%s'\n", outname, outfile);
        fflush(stdout);
    }

    if (!dumper) {
        pcap_perror(pcap, prog_name);
    }

    /* as long as the procfile doesn't send EOF, keep reading */
    npkts = 0;
    while (0 < (nbytes = read(pd, buf, BUFSZ))) {
        pkt = (struct pna_packet *)buf;

        /* make sure the buffer holds all the data we expect */
        printf("got %d bytes\n", nbytes);
        fflush(stdout);
        if (nbytes != pkt->data_len) {
            /* it does not, ignore this packet */
            fprintf(stderr, "did not capture entire packet\n");
            continue;
        }

        /* fill out header info and write out packet to pcap file */
        hdr.ts = pkt->ts;
        hdr.len = pkt->pkt_len;
        hdr.caplen = pkt->data_len - sizeof(*pkt);
        pcap_dump((u_char *)dumper, &hdr, (u_char *)pkt->data);
        npkts += 1;

        /* enough packets in this trace, create a new one */
        if (PKTS_PER_TRACE == npkts) {
            npkts = 0;
            pcap_dump_close(dumper);

            /* prep a new file for output */
            start = time(NULL);
            start_gmt = gmtime((time_t *)&start);
            strftime(outfile, MAXNAMLEN, outname, start_gmt);
            dumper = pcap_dump_open(pcap, outfile);
        }
        else {
            pcap_dump_flush(dumper);
        }
    }

    /* close pcap object */
    pcap_close(pcap);

    /* close the procfile when done */
    close(pd);
}

