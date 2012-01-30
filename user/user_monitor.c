/**
 * Copyright 2011 Washington University in St Louis
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

/* simple null key */
static struct pna_flowkey null_key = {
	.l3_protocol = 0,
	.l4_protocol = 0,
	.local_ip = 0,
	.remote_ip = 0,
	.local_port = 0,
	.remote_port = 0,
};


/* global variables */
int verbose = 0;
char *prog_name;

int flowkey_match(struct pna_flowkey *key_a, struct pna_flowkey *key_b)
{
	return !memcmp(key_a, key_b, sizeof(*key_a));
}

/* flushes a buffer out to the file */
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

/* dumps the in-memory table to a file */
void dump_table(void *table_base, unsigned int table_size, char *out_file)
{
    int fd;
    unsigned int nflows;
    unsigned int nentries;
    unsigned int start_time;
    uint offset;
	unsigned int flow_idx;
    struct flow_entry *flow;
    struct flow_entry *flow_table;
    struct pna_log_hdr *log_header;
    struct pna_log_entry *log;
    char buf[BUF_SIZE];
    int buf_idx;

    /* record the current time */
    start_time = time(NULL);

    nentries = table_size / sizeof(*flow);

    /* open up the output file */
    fd = open(out_file, O_CREAT|O_RDWR);
    if (fd < 0) {
        perror("open out_file");
        return;
    }
    fchmod(fd, S_IRUSR | S_IRGRP | S_IROTH);
    lseek(fd, sizeof(struct pna_log_hdr), SEEK_SET);

    buf_idx = 0;
    nflows = 0;

	flow_table = (struct flow_entry *)table_base;

    /* now we loop through the tables ... */
    for (flow_idx = 0 ; flow_idx < nentries; flow_idx++ ) {
        /* get the first level entry */
        flow = &flow_table[flow_idx];

        /* make sure it is active */
        if (flowkey_match(&flow->key, &null_key)) {
            continue;
        }

		/* set up monitor buffer */
		log = (struct pna_log_entry *)&buf[buf_idx];
		buf_idx += sizeof(struct pna_log_entry);

		/* copy the flow entry */
		log->local_ip = flow->key.local_ip;
		log->remote_ip = flow->key.remote_ip;
		log->local_port = flow->key.local_port;
		log->remote_port = flow->key.remote_port;
		log->packets[PNA_DIR_OUTBOUND] = flow->data.packets[PNA_DIR_OUTBOUND];
		log->packets[PNA_DIR_INBOUND] = flow->data.packets[PNA_DIR_INBOUND];
		log->bytes[PNA_DIR_OUTBOUND] = flow->data.bytes[PNA_DIR_OUTBOUND];
		log->bytes[PNA_DIR_INBOUND] = flow->data.bytes[PNA_DIR_INBOUND];
		log->first_tstamp = flow->data.first_tstamp;
		log->l4_protocol = flow->key.l4_protocol;
		log->first_dir = flow->data.first_dir;
		log->pad[0] = 0x00;
		log->pad[1] = 0x00;
		nflows++;

		/* check if we can fit another entry */
		if (buf_idx + sizeof(struct pna_log_entry) >= BUF_SIZE) {
			/* flush the buffer */
			buf_idx = buf_flush(fd, buf, buf_idx);
		}
    }

    /* make sure we're flushed */
    buf_idx = buf_flush(fd, buf, buf_idx);

    /* display the number of entries we got */
    if (verbose) {
        printf("%d flows to '%s' ", nflows, out_file);
    }

    /* write out header data */
    lseek(fd, 0, SEEK_SET);
    log_header = (struct pna_log_hdr *)&buf[buf_idx];
    log_header->start_time = start_time;
    log_header->end_time = time(NULL);
    log_header->size = nflows * sizeof(struct pna_log_entry);
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

    frac = 0;
    while (1) {
        /* sleep for interval (correct for processing time) */
        gettimeofday(&stop, NULL);
        timersub(&stop, &start, &diff);
        /* show processing time if bigger than 100 microseconds */
        if (verbose && diff.tv_usec > 100) {
            printf("processed in %d.%06d seconds (sleeping for %u seconds)\n",
                    diff.tv_sec, diff.tv_usec,
                    interval - diff.tv_sec - frac/USECS_PER_SEC);
        }
        fflush(stdout); fflush(stderr);
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
        dump_table(table_base, size, out_file);

        /* unmmap() for access */
        if (munmap(table_base, size) == -1) {
            perror("munmap");
        }

        /* close file */
        close(fd);
    }

    return 0;
}
