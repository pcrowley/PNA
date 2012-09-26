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
#define USECS_PER_SEC    1000000

/* prototypes */
int session_dump(char *, char *);

/* global variables */
int verbose = 0;
char *prog_name;

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
    char *log_dir = DEFAULT_LOG_DIR;
    int interval = DEFAULT_INTERVAL;

    prog_name = argv[0];
    /* process any arguments */
    while ((opt = getopt(argc, argv, "i:d:v")) != -1) {
        switch (opt) {
        case 'd': log_dir  = optarg;       break;
        case 'i': interval = atoi(optarg); break;
        case 'v': verbose  = 1;            break;
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

    /* dump the file */
    session_dump(log_dir, argv[0]);

    return 0;
}
