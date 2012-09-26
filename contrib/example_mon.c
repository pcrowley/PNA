/**
 * This is a stub file for creating custom C monitors for the PNA.
 * For an example implementation, see pcap_dump.c which uses this as the
 * base and creates a hook that simple writes a PCAP file for the packets.
 */
#include <stdio.h>

#include "pna.h"

void monitor_init(void);
void monitor_release(void);
void monitor_hook(struct session_key *, int, struct pna_packet *);

/**
 * PNA monitor configuration.
 * You need to define your .init, .release, and .hook callbacks.
 * pna_main will fill in the verbose, prog_name, and log_dir variables
 * (among others).
 */
struct pna_config cfg = {
    .init = NULL,
    .release = NULL,
    .hook = monitor_hook,
};

/**
 * Initialization routines for your monitor.
 * Allocate any global resources or initial values here.
 */
void monitor_init(void)
{
    return;
}

/**
 * Release routines for your monitor.
 * Free up or write out any remaining data you may have, the program is
 * exiting.
 */
void monitor_release(void)
{
    return;
}

/**
 * Per-packet hook routine for your monitor.
 * This is the main workhorse. It should be efficient. The parameters are
 * designed to help you access simple data (local/remote ip/port, protocol
 * info, pointers to specific headers, etc.).
 * @param *key contains local+remote ip and port, l3 and l4 protocol
 * @param direction specifies if packet was inbound or outbound
 * @param *pkt wrapper the actual packet data, has length and packet data
 */
void monitor_hook(struct session_key *key, int direction,
                  struct pna_packet *pkt)
{
    return;
}

/**
 * Main routine.
 * This is executed when the PNA detects a matching filter (e.g., if this
 * is an 'http' monitor, an 'http' filter must be registered with the PNA:
 * see service/filter for more details on registering a filter).
 * The parameters that are handed to this program are defined by the pna,
 * so you shouldn't have to deviate too much from this stub.
 */
int main(int argc, char **argv)
{
    pna_main(argc, argv, &cfg);
    pna_monitor(&cfg);
}
