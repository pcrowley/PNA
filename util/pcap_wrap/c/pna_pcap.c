/*
 * This C file should allow for prototyping potential PNA hooks.
 * It takes a PCAP file as input, does some preliminary work on a packet
 * (getting it setup similarly to how it would be passed by the PNA).
 * The only thing you should need to write is the monitor_hook() function
 * and any helpers you need associated with it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "pna.h"

/* monitor prototypes */
void monitor_init(void);
void monitor_hook(struct session_key *, int, struct packet *, unsigned long *);
void monitor_release(void);

/* local prototypes */
void pna_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void sigint_handler(int);

uint pkt_count = 0;

/**
 * Callback for pcap_dispatch, handles a single packet then returns
 */
void pna_callback(u_char *user, const struct pcap_pkthdr *h,
                   const u_char *bytes)
{
    int i = 0;
    int len = h->caplen;
    char *data = (char *)bytes;
    struct ethhdr *eh;
    struct iphdr *ih;
    struct udphdr *uh;
    struct tcphdr *th;
    struct session_key key;
    unsigned int temp;
    int dir = 0;
    unsigned long pipe_data = -1;
    struct packet pkt = { h->caplen, bytes, NULL, NULL, NULL, NULL };

    pkt_count += 1;

    /* we just assume it's Ethernet */
    eh = (struct ethhdr *)data;
    data += sizeof(*eh);
    pkt.eth_hdr = eh;
    key.l3_protocol = ntohs(eh->h_proto);
    if (key.l3_protocol != ETH_P_IP) {
        return;
    }

    /* extract l3 info */
    ih = (struct iphdr *)data;
    data += ((ih->ihl & 0x0f) << 2);
    pkt.ip_hdr = ih;
    key.l4_protocol = ih->protocol;
    key.local_ip = ntohl(ih->saddr);
    key.remote_ip = ntohl(ih->daddr);

    /* extract l4 info */
    if (ih->protocol == IPPROTO_TCP) {
        th = (struct tcphdr *)data;
        data += (th->doff << 2);
        pkt.tcp_hdr = th;
        key.local_port = ntohs(th->source);
        key.remote_port = ntohs(th->dest);
    }
    else if (ih->protocol == IPPROTO_UDP) {
        uh = (struct udphdr *)data;
        pkt.udp_hdr = uh;
        data += sizeof(*uh);
        key.local_port = ntohs(uh->source);
        key.remote_port = ntohs(uh->dest);
    }
    else {
        return;
    }
    pkt.payload = data;

    /* localize */
    temp = key.local_ip & PNA_MASK;
    if (temp == (PNA_PREFIX & PNA_MASK)) {
        // local_ip is local, do nothing
        dir = PNA_DIR_OUTBOUND;
    }
    else {
        // remote_ip is local, swap ips and ports
        temp = key.local_ip;
        key.local_ip = key.remote_ip;
        key.remote_ip = temp;
        temp = key.local_port;
        key.local_port = key.remote_port;
        key.remote_port = temp;
        dir = PNA_DIR_INBOUND;
    }

    monitor_hook(&key, dir, &pkt, &pipe_data);
}

int go = 1;

/**
 * Ctrl-C handler
 */
void sigint_handler(int signal)
{
    printf(" detected, shutting down\n");
    go = 0;
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;

    if (argc != 2)
    {
        printf("usage: %s <file>\n", argv[0]);
        exit(1);
    }

    char *datafile = argv[1];

    if (0 != access(datafile, F_OK)) {
        printf("file does not exist (%s)\n", datafile);
        exit(1);
    }

    monitor_init();

    /* set up PCAP file */
    signal(SIGINT, &sigint_handler);
    pcap = pcap_open_offline(datafile, errbuf);

    while (go)
    {
        if (0 == pcap_dispatch(pcap, 1, &pna_callback, NULL)) {
            break;
        }
    }

    monitor_release();
    printf("Processed %d packets\n", pkt_count);
}

