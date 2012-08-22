/**
 * Copyright 201r21 Washington University in St Louis
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
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>

#include "pna.h"

#define LOG_FN_FORMAT "%s/%%Y%%m%%d%%H%%M%%S-%s.log"

extern int verbose;

/**
 * Given an `out_dir` directory for the output file, append the name and
 * datetime string to it and setup the output file header data, then dump
 * the proc_file into it.
 */
int session_dump(char *out_dir, char *proc_file)
{
    time_t start;
    struct tm *start_gmt;
    int fd;
    void *out_addr;
    uint64_t nentries;
    char out_fmt[MAX_STR];
    char out_file[MAX_STR];
    struct pna_log_header header;
    uint64_t entry_size = sizeof(struct session_entry);

    /* form the output file name and ready it for datetime string */
    snprintf(out_fmt, MAX_STR, LOG_FN_FORMAT, out_dir, basename(proc_file));

    /* get the current time and finish the out_file name */
    start = time(NULL);
    start_gmt = gmtime((time_t *)&start);
    strftime(out_file, MAX_STR, out_fmt, start_gmt);

    /* open up the output file */
    fd = open(out_file, O_CREAT|O_RDWR);
    if (fd < 0) {
        perror("open out_file");
        return -1;
    }
    fchmod(fd, S_IRUSR | S_IRGRP | S_IROTH);

    /* get base address for dumping proc_file (leave header room) */
    lseek(fd, sizeof(header), SEEK_SET);
    nentries = proc_dump(fd, proc_file, entry_size);
    if (nentries == 0) {
        /* nothing was written, delete file? */
        perror("proc_dump");
        goto out_close;
    }

    /* display the number of entries we got */
    if (verbose) {
        printf("dumped %" PRIu64 " entries to '%s'\n", nentries, out_file);
    }

    /* complete the header data */
    lseek(fd, 0, SEEK_SET);
    header.magic[0] = PNA_LOG_MAGIC0;
    header.magic[1] = PNA_LOG_MAGIC1;
    header.magic[2] = PNA_LOG_MAGIC2;
    header.version = PNA_LOG_VERSION;
    header.entries = nentries;
    header.start_time = start;
    header.end_time = time(NULL);
    write(fd, &header, sizeof(header));

out_close:
    /* close the descriptor */
    close(fd);

    return 0;
}
