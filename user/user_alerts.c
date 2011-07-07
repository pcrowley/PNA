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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "pna.h"

#define PNA_ALERT_LOG_FORMAT \
    "%s: pna_alert type:%s, protocol:%s, direction:%s, offender:%s\n"
#define PNA_ALERT_TIME_FORMAT "%F %T"
#define MAX_IP_STR 32
#define MAX_STR 256

/* some useful global variables */
int socket_fd;
struct nlmsghdr *nlh = NULL;
struct msghdr nl_msg;
struct iovec nl_iov;
struct sockaddr_nl pna_user, pna_kernel;
char *prog_name;
FILE *out_file = NULL;
char *handler_path = NULL;

/* prototypes */
void exit_handler(void);
void pna_alert_send(struct pna_alert_msg *alert);
void sig_handler(int signal);
void pna_alert_recv(struct pna_alert_msg *alert);

void exit_handler(void)
{
    struct pna_alert_msg unreg;

    if (socket_fd > 0) {
        /* send unregister message */
        unreg.command = PNA_ALERT_CMD_UNREGISTER;
        unreg.value = getpid();
        pna_alert_send(&unreg);

        /* close the socket */
        close(socket_fd);
    }

    /* free up space */
    free(nlh);
}

void sig_handler(int signal)
{
    /* signal handler just exits cleanly */
    exit(0);
}

void pna_alert_send(struct pna_alert_msg *alert)
{
    /* put data to send in packet */
    memcpy(NLMSG_DATA(nlh), alert, PNA_ALERT_MSG_SZ);

    /* send the message */
    if (sendmsg(socket_fd, &nl_msg, 0) < 0) {
        perror("sendmsg");
    }
}

void pna_alert_recv(struct pna_alert_msg *alert)
{
    int type_i, proto_i, dir_i;
    char *type, *proto, *dir, tstamp[MAX_STR];
    int ip_i[4];
    char ip[MAX_IP_STR];
    struct tm *time;

    if (alert->command != PNA_ALERT_CMD_WARN) {
        printf("unknown command: %d\n", alert->command);
        return;
    }

    type_i = (alert->reason & PNA_ALERT_TYPE_MASK) >> PNA_ALERT_TYPE_SHIFT;
    proto_i = (alert->reason & PNA_ALERT_PROTO_MASK) >> PNA_ALERT_PROTO_SHIFT;
    dir_i = (alert->reason & PNA_ALERT_DIR_MASK) >> PNA_ALERT_DIR_SHIFT;

    type = pna_alert_types[type_i];
    proto = pna_alert_protocols[proto_i];
    dir = pna_alert_directions[dir_i];
    ip_i[0] = (alert->value & 0xff000000) >> 24;
    ip_i[1] = (alert->value & 0x00ff0000) >> 16;
    ip_i[2] = (alert->value & 0x0000ff00) >> 8;
    ip_i[3] = (alert->value & 0x000000ff) >> 0;
    snprintf(ip, MAX_IP_STR, "%d.%d.%d.%d",
            ip_i[0], ip_i[1], ip_i[2], ip_i[3]);

    strftime(tstamp, MAX_STR, PNA_ALERT_TIME_FORMAT,
            localtime(&alert->timeval.tv_sec));
//    snprintf(tstamp, MAX_STR, "%u", alert->timeval.tv_sec);

    if (out_file != NULL) {
        fprintf(out_file, PNA_ALERT_LOG_FORMAT, tstamp, type, proto, dir, ip);
    }

    if (handler_path != NULL) {
        if (fork() == 0) {
            /* child can exec */
            if (execl(handler_path, handler_path, type, proto, dir, ip, (char *)NULL) < 0) {
                perror("could not execute handler");
            }
        }
    }
}

void usage(void)
{
    int i, size;

    printf("usage: %s [-o <logfile>] [-h <handler>]\n", prog_name);
    printf("\t-o <logfile>\toutput alert messages to <logfile>\n");
    printf("\t-h <handler>\texecute <handler> with alert as arguments\n");
    printf("You must specify <logfile> and/or <handler> to run this program\n");
    printf("\nArguments for <handler> will be in the following order:\n");
    printf("\t<type> <protocol> <direction> <offending-ip>\n");
    printf("where\n");

    printf("\t<type> is ", sizeof(pna_alert_types));
    size = sizeof(pna_alert_types) / sizeof(char *);
    for (i = 0; i < size-1; i++) {
        printf("%s, ", pna_alert_types[i]);
    }
    printf("or %s\n", pna_alert_types[i]);

    printf("\t<protocol> is ", sizeof(pna_alert_protocols));
    size = sizeof(pna_alert_protocols) / sizeof(char *);
    for (i = 0; i < size-1; i++) {
        printf("%s, ", pna_alert_protocols[i]);
    }
    printf("or %s\n", pna_alert_protocols[i]);

    printf("\t<direction> is ", sizeof(pna_alert_directions));
    size = sizeof(pna_alert_directions) / sizeof(char *);
    for (i = 0; i < size-1; i++) {
        printf("%s, ", pna_alert_directions[i]);
    }
    printf("or %s\n", pna_alert_directions[i]);

    exit(1);
}

int main(int argc, char **argv)
{
    char opt;
    struct pna_alert_msg reg;

    prog_name = argv[0];
    /* process options */
    while ((opt = getopt(argc, argv, "o:h:")) != -1) {
        switch (opt) {
            case 'o':
                if (strcmp(optarg, "-") == 0) {
                    out_file = stdout;
                }
                else {
                    out_file = fopen(optarg, "w");
                    if (out_file == NULL) {
                        perror("fopen");
                        exit(1);
                    }
                }
                break;
            case 'h':
                handler_path = optarg;
                break;
            case '?':
            default:
                usage();
        }
    }

    if (out_file == NULL && handler_path == NULL) {
        usage();
    }

    /* set the cleanup exit handler */
    atexit(exit_handler);

    /* signal handler for termination cases */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* allocate space for messages */
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(PNA_ALERT_MSG_SZ));
    memset(nlh, 0, NLMSG_SPACE(PNA_ALERT_MSG_SZ));

    /* set up netlink header structure for packets */
    nlh->nlmsg_len = NLMSG_SPACE(PNA_ALERT_MSG_SZ);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    nl_iov.iov_base = (void *)nlh;
    nl_iov.iov_len = NLMSG_SPACE(PNA_ALERT_MSG_SZ);

    /* Linux can be picky about msghdrs, 0 it out */
    memset(&nl_msg, 0, sizeof(nl_msg));
    nl_msg.msg_name = (void *)&pna_kernel;
    nl_msg.msg_namelen = sizeof(pna_kernel);
    nl_msg.msg_iov = &nl_iov;
    nl_msg.msg_iovlen = 1;

    /* set up my (userspace) socket identifier */
    memset(&pna_user, 0, sizeof(pna_user));
    pna_user.nl_family = AF_NETLINK;
    pna_user.nl_pid = getpid();

    /* set up target (kernel) socket identifier */
    memset(&pna_kernel, 0, sizeof(pna_kernel));
    pna_kernel.nl_family = AF_NETLINK;
    pna_kernel.nl_pid = 0; /* i.e. Linux Kernel */
    pna_kernel.nl_groups = 0; /* unicast */

    /* create netlink socket with PNA */
    socket_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_PNA);
    if (socket_fd < 0) {
        perror("socket");
        return -1;
    }

    /* associate ourselves with the socket */
    if (bind(socket_fd, (struct sockaddr *)&pna_user, sizeof(pna_user)) < 0) {
        perror("bind");
        return -1;
    }

    /* send register message */
    reg.command = PNA_ALERT_CMD_REGISTER;
    reg.value = getpid();
    pna_alert_send(&reg);

    /* Read messages from kernel */
    while (1) {
        if (recvmsg(socket_fd, &nl_msg, 0) < 0) {
            perror("recvmsg");
        }
        pna_alert_recv((struct pna_alert_msg *)NLMSG_DATA(nlh));
    }
}
