/**
 * This is a glue file. It binds the underlying PNA technology to a user
 * written monitor. It should require no modification, just calls the
 * pna_main() and pna_monitor(). See example_mon.c for use.
 *
 * There is also support for:
 *  - Python (pna.py)
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

#define DEFAULT_LOG_DIR "./logs"
#define BUFSZ 2048

int pna_monitor(struct pna_config *config)
{
    int pd;
    ssize_t nbytes;
    char buf[BUFSZ];
    struct pna_packet *pkt;

    /* call the monitor initialization routine */
    if (config->init) {
        config->init();
    }

    /* open the procfile for reading */
    pd = open(config->proc_file, O_RDONLY);
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
        if (nbytes != pkt->caplen + sizeof(*pkt)) {
            /* it does not, ignore this packet */
            fprintf(stderr, "did not capture entire packet\n");
            continue;
        }

        /* call the monitor hook function with params */
        if (config->hook) {
            config->hook(&pkt->key, pkt->direction, pkt);
        }
    }

    /* close the procfile when done */
    close(pd);

    /* call any monitor release routines */
    if (config->release) {
        config->release();
    }
}

static void pna_usage(struct pna_config *config)
{
    printf("usage: %s [-v] [-d <logdir>]\n", config->prog_name);
    printf("\t-v\tverbose mode (show quantities and time information)\n");
    printf("\t-d <logdir>\tsave logs to <logdir> (default: %s)\n",
                                    DEFAULT_LOG_DIR);
    exit(1);
}

int pna_main(int argc, char **argv, struct pna_config *config)
{
    char opt;

    config->prog_name = argv[0];
    config->log_dir = DEFAULT_LOG_DIR;
    config->verbose = 0;

    /* process any arguments */
    while ((opt = getopt(argc, argv, "e:d:v")) != -1) {
        switch (opt) {
            case 'd':
                config->log_dir = optarg;
                break;
            case 'v':
                config->verbose = 1;
                break;
            case 'e':
                break;
            case '?':
            default:
                pna_usage(config);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1) {
        pna_usage(config);
    }

    config->proc_file = argv[0];

    if (config->verbose) {
        printf("running %s with %s\n", config->prog_name, config->proc_file);
    }

    return 0;
}

