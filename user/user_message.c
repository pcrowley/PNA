/**
 * Copyright 2012 Washington University in St Louis
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
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "pna.h"

#define ALERT             "alert" /**< Name of external alert executable */
#define ALERT_LOG_FORMAT  "%s - %s"
#define ALERT_TIME_FORMAT "%a, %d %b %Y %T %z" /**< RFC 2822 compliant */
#define DEFAULT_LOG_DIR   "./logs"
#define DEFAULT_EXEC_DIR  "./user"

/* prototypes */
int session_dump(char *, char *);

/* some structures */
struct thread_map {
    int in_use;
    pthread_t thread_id;
    struct timeval timeval;
    char data[PNA_MSG_DATA_LEN];
};

struct builtin {
    char *name;
    int (*func)(char *, char *);
};

/* global variables */
char *prog_name;
char *log_dir = DEFAULT_LOG_DIR;
char *exec_dir = DEFAULT_EXEC_DIR;
int verbose = 0;
struct thread_map threads[PNA_MSG_NTHREADS];
struct builtin builtins[] = {
    { .name = "session", .func = session_dump },
};

/*
 * handler functions
 */
void exit_handler(void)
{
    /* unregister the handler */
    pna_message_unreg();

    /* clean up the message system */
    pna_message_uninit();
}

void sig_handler(int signal)
{
    /* signal handler just exits cleanly */
    exit(0);
}

/* if executable file in working dir, use as override */
int override_exists(char *name)
{
    char command[MAX_STR];
    snprintf(command, MAX_STR, "%s/%s", exec_dir, name);
    return (0 == access(command, R_OK | X_OK));
}

/* go through table of built-ins and check for match */
void *builtin(char *name)
{
    int i;
    int n_builtins = sizeof(builtins) / sizeof(*builtins);

    for (i = 0; i < n_builtins; i++) {
        if (0 == strncmp(name, builtins[i].name, MAX_STR)) {
            /* match */
            return builtins[i].func;
        }
    }

    return NULL;
}

/*
 * thread handlers and wrappers
 */
char *rpeel(char *dst, char *src, char c)
{
    char *base, *dash;

    /* strip any directories */
    base = basename(src);
    /* copy string into final dest */
    strncpy(dst, base, MAX_STR);
    /* find last instance of c */
    dash = strrchr(dst, c);
    if (dash)
        *dash = '\0';

    return dst;
}

void *clear_entry(struct thread_map *entry)
{
    /* safe to clear entry as long as in_use is last */
    memset(&entry->data, 0, PNA_MSG_DATA_LEN);
    entry->in_use = 0;

    return entry;
}

/* once thread just executes once then exits, nothing too hard */
void *once_thread(void *data)
{
    void *(*fn)(char *, char *);
    struct thread_map *entry = data;
    char *dash;
    char *base;
    char name[MAX_STR];
    char command[MAX_STR];

    /* copy name into local buffer and strip everything after last - */
    rpeel(name, entry->data, '-');

    /* see if there is an external file for override use */
    if (override_exists(name)) {
        /* there is an external file, use it */
        snprintf(command, MAX_STR, "%s/%s %s", exec_dir, name, entry->data);
        system(command);
        if (verbose) {
            printf("using external handler: `%s` (ONCE)\n", command);
        }
    }
    else if (NULL != (fn = builtin(name))) {
        /* handler is built-in, use it */
        if (verbose) {
            printf("using built-in handler for %s (ONCE)\n", entry->data);
        }
        fn(log_dir, entry->data);
    }
    else {
        fprintf(stderr, "ONCE no handler for %s\n", name);
    }

    return clear_entry(entry);
}

/* poll thread executes in a loop, each time calling a helper */
void *poll_thread(void *data)
{
    void *(*fn)(char *, char *);
    char name[MAX_STR];
    char command[MAX_STR];
    struct thread_map *entry = data;
#define POLL_NONE     0
#define POLL_EXTERNAL 1
#define POLL_BUILTIN  2
    int type = POLL_NONE;

    /* copy name into local buffer and strip everything after last - */
    rpeel(name, entry->data, '-');

    /* determine if there is an external handler */
    if (override_exists(name)) {
        type = POLL_EXTERNAL;
        snprintf(command, MAX_STR, "%s/%s %s", exec_dir, name, entry->data);
        if (verbose) {
            printf("using external handler: `%s` (POLL)\n", command);
        }
    }
    else if (NULL != (fn = builtin(name))) {
        type = POLL_BUILTIN;
        if (verbose) {
            printf("using built-in handler for %s (POLL)\n", entry->data);
        }
    }
    else {
        type = POLL_NONE;
        fprintf(stderr, "no handler for %s\n", entry->data);
        return NULL;
    }

    while (1 /* more data */) {
        switch (type) {
            case POLL_EXTERNAL:
                system(command);
                break;
            case POLL_BUILTIN:
                fn(log_dir, entry->data);
                break;
        }

        sleep(1);
    }

    return NULL;
}

/* alert thread executes once */
void *alert_thread(void *data)
{
    char command[MAX_STR];
    char tstamp[MAX_STR];
    int has_override = 0;
    struct thread_map *entry = data;

    /* get the time of the event */
    strftime(tstamp, MAX_STR, ALERT_TIME_FORMAT, localtime(&entry->timeval.tv_sec));

    /* if there is an external script, use that */
    has_override = override_exists(ALERT);
    if (has_override) {
        snprintf(command, MAX_STR, "%s/%s '%s' '%s'", exec_dir, ALERT,
                 entry->data, tstamp);
        system(command);
        if (verbose) {
            printf("using ALERT handler: `%s`\n", command);
        }
    }

    /* otherwise, write to stdout */
    if (verbose || !has_override) {
        printf(ALERT_LOG_FORMAT, tstamp, entry->data);
    }

    return clear_entry(entry);;
}

int spawn_thread(struct thread_map *entry, void *(*thread)(void *))
{
    /* create pthread to handle routine */
    if (0 != pthread_create(&entry->thread_id, NULL, thread, entry)) {
        perror("pthread_create");
        return -1;
    }
    return 0;
}

void stop_thread(struct thread_map *entry)
{
    /* XXX: Probably shouldn't be kill -9... */
    pthread_kill(entry->thread_id, 9);
}

/*
 * main driver
 */
void usage(void)
{
    printf("usage: %s [-v] [-d <logdir>] [-e <execdir>\n", prog_name);
    printf("\t-v\tverbose mode (show quantities and time information)\n");
    printf("\t-d <logdir>\tsave logs to <logdir> (default: %s)\n",
                                    DEFAULT_LOG_DIR);
    printf("\t-e <execdir>\tdirectory holding run-time executables (default: %s)\n",
                                    DEFAULT_EXEC_DIR);
    exit(1);
}

int main(int argc, char **argv)
{
    int i;
    char opt;
    uint32_t pid;
    struct thread_map *entry;
    struct pna_message *message;

    /* command line setup */
    prog_name = argv[0];

    /* process any arguments */
    while ((opt = getopt(argc, argv, "e:d:v")) != -1) {
        switch (opt) {
            case 'd':
                log_dir = optarg;
                break;
            case 'e':
                exec_dir = optarg;
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

    /* signals/cleanup handlers */
    atexit(exit_handler);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* setup netlink object */
    if (0 != pna_message_init())
    {
        exit(1);
    }

    /* send register message */
    pna_message_reg();

    while (1) {
        /* wait for message from kernel */
        message = pna_message_recv();
        if (!message) {
            continue;
        }


        /* check for correct registration */
        if (message->command == PNA_MSG_CMD_REGISTER) {
            pid = *(uint32_t *)message->data;
            if (pid == getpid()) {
                printf("registered with kernel module (%d)\n", pid);
                continue;
            }
            fprintf(stderr, "invalid registration, waiting for correct\n");
        }

        /* make sure we can understand this message */
        if (message->command != PNA_MSG_CMD_SIGNAL) {
            fprintf(stderr, "command not recognized (%d)\n", message->command);
            continue;
        }

        if (verbose) {
            printf("received: {%d, %d, '%s'}\n", message->command,
                    message->method, message->data);
        }
        /* find free entry in thread map */
        /* n.b. allocation happens serially, no need to lock */
        entry = NULL;
        for (i = 0; i < PNA_MSG_NTHREADS; i++) {
            if (0 == threads[i].in_use) {
                /* free entry found */
                entry = &threads[i];
                entry->in_use = 1;
                break;
            }
        }
        if (!entry) {
            fprintf(stderr, "no thread for signal method\n");
            continue;
        }

        /* All except STOP has meaningful entry, populate it */
        if (message->method != PNA_MSG_METH_STOP) {
            memcpy(entry->data, message->data, PNA_MSG_DATA_LEN);
            memcpy(&entry->timeval, &message->timeval, sizeof(struct timeval));
        }

        switch (message->method) {
            case PNA_MSG_METH_POLL:
                /* if POLL, start thread using poll_thread */
                spawn_thread(entry, poll_thread);
                break;
            case PNA_MSG_METH_ONCE:
                /* if ONCE, start thread using once_thread */
                spawn_thread(entry, once_thread);
                break;
            case PNA_MSG_METH_ALERT:
                /* if ALERT, start thread using alert_thread */
                spawn_thread(entry, alert_thread);
                break;
            case PNA_MSG_METH_STOP:
                /* if STOP, find thread matching file and kill */
                stop_thread(entry);
                break;
        }
    }
}

