#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>

#include "pna.h"

#define DEFAULT_LOG_DIR  "./logs"
#define DEFAULT_INTERVAL 10
#define LOG_FILE_FORMAT  "%s/pna-%%Y%%m%%d%%H%%M%%S-%s.log"
#define MAX_STR          1024
#define BUF_SIZE         (1 * 1024 * 1024)
#define USECS_PER_SEC    1000000

/* log file format structures */
struct watch_port {
    ushort local_port;
    ushort remote_port;
    uint npkts[PNA_DIRECTIONS];
    uint nbytes[PNA_DIRECTIONS];
    uint timestamp;
    uchar first_dir;
    uchar pad[3];
};

struct pna_log_hdr {
    unsigned int timestamp;
    unsigned int size;
};

struct watch_data {   
    uint local_ip;
    uint remote_ip;
};

/* global variables */
int verbose = 0;
char *prog_name;

int buf_flush(int out_fd, char *buffer, int buf_idx)
{
    int count;

    while (buf_idx > 0) {
        count = write(out_fd, buffer, buf_idx);
        if (count < 0) {
            perror("write");
        }
        buf_idx -= count;
    }

    return buf_idx;
}

void dump_table(void *table_base, char *out_file)
{
    int fd;
    uint nips, nports;
    uint offset;
    struct lip_entry *lips;
    struct rip_entry *rips;
    struct port_entry *ports[PNA_PROTOS];
    struct lip_entry *lip_entry;
    struct rip_entry *rip_entry;
    struct port_entry *port_entry;
    struct pna_log_hdr *log_header;
    int lip_idx, rip_idx, proto_idx, port_idx;
    char buf[BUF_SIZE];
    int buf_idx;
    struct watch_data *monitor;
    struct watch_port *port;
    pna_bitmap bitmap;

    /* open up the output file */
    fd = open(out_file, O_CREAT|O_RDWR);
    if (fd < 0) {
        perror("open out_file");
        return;
    }
    fchmod(fd, S_IRUSR | S_IRGRP | S_IROTH);
    lseek(fd, sizeof(struct pna_log_hdr), SEEK_SET);

    offset = 0;
    lips = table_base + offset;
    offset += PNA_SZ_LIP_ENTRIES; 
    rips = table_base + offset;
    offset += PNA_SZ_RIP_ENTRIES;
    ports[PNA_PROTO_TCP] = table_base + offset;
    offset += PNA_SZ_PORT_ENTRIES;
    ports[PNA_PROTO_UDP] = table_base + offset;
    offset += PNA_SZ_PORT_ENTRIES;

    buf_idx = 0;
    nips = 0;
    nports = 0;

    /* now we loop through the tables ... */
    for (lip_idx = 0; lip_idx < PNA_LIP_ENTRIES; lip_idx++ ) {
        /* get the first level entry */
        lip_entry = &lips[lip_idx];

        /* make sure it is active */
        if ( 0 == lip_entry->local_ip ) {
            continue;
        }

        for (rip_idx = 0; rip_idx < PNA_RIP_ENTRIES; rip_idx++ ) {
            /* check if a subset of remote IPs have been used */
            if ((0 == rip_idx % BITMAP_BITS) &&
                (0 == lip_entry->dsts[rip_idx/BITMAP_BITS]) ) {
                /* nope, we can skip this subset */
                rip_idx += (BITMAP_BITS-1);
                continue;
            }

            /* now check if the local IP uses this specific remote IP */
            if ( 0 == (lip_entry->dsts[rip_idx/BITMAP_BITS]
                        & (1 << rip_idx % BITMAP_BITS)) ) {
                /* it isn't, keep moving */
                continue;
            }

            /* get the second level entry */
            rip_entry = &rips[rip_idx];

            /* set up monitor buffer */
            monitor = (struct watch_data *)&buf[buf_idx];

            /* copy the local, remote IP pair */
            monitor->local_ip = lip_entry->local_ip;
            monitor->remote_ip = rip_entry->remote_ip;
            buf_idx += sizeof(struct watch_data);
            nips++;

            /* now we can just dump, set up port pointer */
            for (proto_idx = 0; proto_idx < PNA_PROTOS; proto_idx++) {
                for (port_idx = 0; port_idx < PNA_PORT_ENTRIES; port_idx++) {
                    bitmap = rip_entry->prts[proto_idx][port_idx/BITMAP_BITS];

                    /* check if a subset of ports has been used */
                    if ((0 == port_idx % BITMAP_BITS) && (0 == bitmap)) {
                        /* it is not, skip ahead */
                        port_idx += (BITMAP_BITS-1);
                        continue;
                    }

                    /* check if port pair is part of this connection */
                    if (0 == (bitmap & (1 << (port_idx % BITMAP_BITS)))) {
                        /* it is not, skip ahead */
                        continue;
                    }

                    /* check if we have the room for this entry */
                    if (buf_idx + sizeof(struct watch_port) >= BUF_SIZE) {
                        /* flush the buffer */
                        buf_idx = buf_flush(fd, buf, buf_idx);
                    }

                    /* get the third level entry */
                    port_entry = &ports[proto_idx][port_idx];

                    /* write to file */
                    port = (struct watch_port *)&buf[buf_idx];
                    port->local_port = port_entry->local_port;
                    port->remote_port = port_entry->remote_port;
                    port->npkts[PNA_DIR_INBOUND] = port_entry->npkts[PNA_DIR_INBOUND];
                    port->npkts[PNA_DIR_OUTBOUND] = port_entry->npkts[PNA_DIR_OUTBOUND];
                    port->nbytes[PNA_DIR_INBOUND] = port_entry->nbytes[PNA_DIR_INBOUND];
                    port->nbytes[PNA_DIR_OUTBOUND] = port_entry->nbytes[PNA_DIR_OUTBOUND];
                    port->timestamp= port_entry->timestamp;
                    port->first_dir = (port_entry->info_bits&0x0c) >> PNA_DIRECTIONS;
                    port->pad[0] = 0x00;
                    port->pad[1] = 0x00;
                    port->pad[2] = 0x00;
                    buf_idx += sizeof(struct watch_port);
                    nports++;
                }

                /* check if we can fit the sentinal */
                if (buf_idx + sizeof(struct watch_port) >= BUF_SIZE) {
                    /* flush the buffer */
                    buf_idx = buf_flush(fd, buf, buf_idx);
                }

                /* insert a sentinal entry (all zeros) */
                memset((void *)&buf[buf_idx], 0, sizeof(struct watch_port));
                buf_idx += sizeof(struct watch_port);
            }

            /* flush before next remote IP round */
            buf_idx = buf_flush(fd, buf, buf_idx);
        }
    }

    /* make sure we're flushed */
    buf_idx = buf_flush(fd, buf, buf_idx);

    /* display the number of entries we got */
    if (verbose) {
        printf("%d ports, %d <lip,rip> to '%s' ", nports, nips, out_file);
    }

    /* write out header data */
    lseek(fd, 0, SEEK_SET);
    log_header = (struct pna_log_hdr *)&buf[buf_idx];
    log_header->timestamp = time(NULL);
    log_header->size = nips * sizeof(struct watch_data);
    log_header->size += nports * sizeof(struct watch_port);
    write(fd, log_header, sizeof(log_header));

    close(fd);
}

void usage(void)
{
    printf("usage: %s [-v] [-d <logdir>] [-i <interval] <procfile>\n", prog_name);
    printf("\t-v\tverbose mode (show quantities and time information)\n");
    printf("\t-d <logdir>\tsave logs to <logdir> (default: %s)\n",
            DEFAULT_LOG_DIR);
    printf("\t-i <interval>\texecute once per <interval> (default: %d)\n",
            DEFAULT_INTERVAL);
    printf("\t<procfile>\tfile containing PNA tables to watch\n");
    exit(1);
}

int main(int argc, char **argv)
{
    char opt;
    char *proc_file;
    char out_base[MAX_STR], out_file[MAX_STR];
    int fd, out_fd;
    struct stat pf_stat;
    size_t size;
    void *table_base;
    struct timeval start, stop, diff;
    unsigned int remainder, frac;
    struct tm *start_tm;
    char *log_dir = DEFAULT_LOG_DIR;
    int interval = DEFAULT_INTERVAL;

    gettimeofday(&start, NULL);

    prog_name = argv[0];
    /* process any arguments */
    while ((opt = getopt(argc, argv, "i:d:v")) != -1) {
        switch (opt) {
        case 'd':
            log_dir = optarg;
            break;
        case 'i':
            interval = atoi(optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        case '?':
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    /* get the proc file from command line */
    if (argc != 1) {
        usage();
    }
    proc_file = argv[0];

    /* fetch size of proc file (used for mmap) */
    if (stat(proc_file, &pf_stat) != 0) {
        perror("stat");
        return -1;
    }
    size = pf_stat.st_size;

    snprintf(out_base, MAX_STR, LOG_FILE_FORMAT, log_dir, basename(proc_file));

    while (1) {
        /* sleep for interval (correct for processing time) */
        gettimeofday(&stop, NULL);
        timersub(&stop, &start, &diff);
        /* show processing time if bigger than 100 microseconds */
        if (verbose && diff.tv_usec > 100) {
            printf("processed in %d.%06d seconds (sleeping for %d seconds)\n",
                    diff.tv_sec, diff.tv_usec,
                    interval - diff.tv_sec - frac/USECS_PER_SEC);
        }
        remainder = sleep(interval - diff.tv_sec - frac/USECS_PER_SEC);
        if (remainder != 0) {
            continue;
        }

        /* detect accumulating slippage */
        if ( frac >= USECS_PER_SEC ) {
            frac -= USECS_PER_SEC;
        }
        frac += diff.tv_usec;

        /* begin processing */
        gettimeofday(&start, NULL);

        /* attempt to proc_open file */
        fd = open(proc_file, O_RDONLY);
        if (fd < 0) {
            if (errno == EACCES) {
                /* EACCES means the file was not used */
                /* we can just skip this round */
                continue;
            }
            perror("open proc_file");
            return -1;
        }

        /* mmap() for access */
        table_base = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
        if (table_base == MAP_FAILED) {
            perror("mmap");
            close(fd);
            continue;
        }

        /* figure out (time based) name of output file */
        start_tm = localtime((time_t *)&start);
        strftime(out_file, MAX_STR, out_base, start_tm);

        /* perform dumping ... */
        dump_table(table_base, out_file);

        /* unmmap() for access */
        if (munmap(table_base, size) == -1) {
            perror("munmap");
        }

        /* close file */
        close(fd);
    }

    return 0;
}
