#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <netdb.h>

#include "../include/nf_ses_watch.h"

#define BUFSZ_WATCH 32
#define BUFSZ_BYTES (BUFSZ_WATCH * sizeof(struct watch_data))

#define TSLEN 16 /* length of timestamp */

int main(int argc, char **argv)
{
    FILE *logfd;
    struct stat logdir_st;
    char *proto_str;
    char *dst_port_str;
    char logfn[NAME_MAX];
    char logtime[NAME_MAX];
    char procfn[NAME_MAX];
    time_t filetime, currtime;
    int procfd;
    char ts[TSLEN];
    struct watch_data buffer[BUFSZ_WATCH];
    struct servent *servent;
    unsigned int buf_totlen;
    int i, buf_rdlen, line_num;
    int smpid;
    int to_stdout = 0;

    if (argc < 2)
    {
        fprintf(stderr, "usage: %s <smpid> [-]\n", argv[0]);
        exit(1);
    }

    smpid = atoi(argv[1]);

    if (argc == 3 && (strncmp(argv[2], "-", 1) == 0))
    {
        to_stdout = 1;
    }

    /* make sure the log directory exists */
    if ( to_stdout != 1 && stat(LOGDIR, &logdir_st) != 0 )
    {
        fprintf(stderr, "'%s' does not exist for log files, exiting...\n",
                LOGDIR);
        exit(1);
    }


    /* construct procfile name */
    sprintf(procfn, "/proc/%s/%d", PROCDIR, smpid);

    /* get the current time and format logfile name */
    filetime = 0;
    currtime = time(NULL);

    for ( ; ; )
    {
        /* see if it is time for a new file */
        if (difftime(currtime, filetime) > LOGROTATE)
        {
            filetime = currtime;
            strftime(logtime, NAME_MAX, TIMEFMT, localtime(&filetime));
            snprintf(logfn, NAME_MAX, "%s/%s-%d-%s.log", 
                     LOGDIR, PROCDIR, smpid, logtime);
        }

        /* open logfile for writing */
        if ( 0 == to_stdout)
        {
            logfd = fopen(logfn, "a");
            if ( NULL == logfd )
            {
                fprintf(stderr, "could not open log file '%s'\n", logfn);
                return -1;
            }
        }
        else
        {
            logfd = stdout;
        }

        /* open procfile */
        procfd = open(procfn, O_RDONLY);
        if ( procfd < 0 )
        {
            fprintf(stderr, "could not open procfile '%s'\n", procfn);
            return -2;
        }

        /* get current time */
        currtime = time(NULL);

        /* format timestamp into string */
        strftime(ts, TSLEN, "%b %d %H:%M:%S", localtime(&currtime));

        /* reset some tallies */
        line_num = 0;
        buf_totlen = 0;

        /* while data is in buffer (read) */
        while ( 0 < (buf_rdlen = read(procfd, buffer, BUFSZ_BYTES)) )
        {
            buf_totlen += buf_rdlen;

            buf_rdlen /= sizeof(struct watch_data);
            for (i = 0; i < buf_rdlen; i++)
            {
                /* write to log */
                fprintf(logfd, "%s ", ts);
                fprintf(logfd, "(%02x:%02x:%02x:%02x:%02x:%02x) ",
                        buffer[i].src_mac[0], buffer[i].src_mac[1],
                        buffer[i].src_mac[2], buffer[i].src_mac[3],
                        buffer[i].src_mac[4], buffer[i].src_mac[5]);
                fprintf(logfd, "%u.%u.%u.%u ",
                        (buffer[i].src_ip >> 24) & 0xFF,
                        (buffer[i].src_ip >> 16) & 0xFF,
                        (buffer[i].src_ip >>  8) & 0xFF,
                        (buffer[i].src_ip >>  0) & 0xFF);
                fprintf(logfd, "-> %u.%u.%u.%u via ",
                        (buffer[i].dst_ip >> 24) & 0xFF,
                        (buffer[i].dst_ip >> 16) & 0xFF,
                        (buffer[i].dst_ip >>  8) & 0xFF,
                        (buffer[i].dst_ip >>  0) & 0xFF);
                fprintf(logfd, "%u TCPs (%u pkts/%u Bytes), ",
                        buffer[i].nprts[NF_SESSION_TCP],
                        buffer[i].npackets[NF_SESSION_TCP],
						buffer[i].nbytes[NF_SESSION_TCP]);
                fprintf(logfd, "%u UDPs (%u pkts/%u Bytes)",
                        buffer[i].nprts[NF_SESSION_UDP],
                        buffer[i].npackets[NF_SESSION_UDP],
						buffer[i].nbytes[NF_SESSION_UDP]);

                fprintf(logfd, "\n");
            }

            line_num += i;
        }

        /* check if there were errors on read */
        if ( buf_rdlen < 0 )
        {
            fprintf(stderr, "error %d while reading '%s'\n", 
                    buf_rdlen, procfn);
        }

        /* close files */
        close(procfd);
        if (0 == to_stdout)
        {
            fclose(logfd);
        }

        /* wait for more packets to come in */
        sleep(LOGSLEEP);
    }
}
