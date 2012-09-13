#!/usr/bin/env python
"""
This is a stub file for creating custom python monitors for the PNA.
For an example implementation, see http_sniffer.py which uses this as the
base and creates a hook that snoops HTTP packets for matching strings.
"""

import pna, sys

def monitor_init() :
    """
    Initialization routines for your monitor.
    Allocate any global resources or initial values here.
    """
    pass

def monitor_release() :
    """
    Release routines for your monitor.
    Free up or write out any remaining data you may have, the program is
    exiting.
    """
    pass

def monitor_hook(key, direction, packet):
    """
    Per-packet hook routine for your monitor.
    This is the main workhorse. It should be efficient. The parameters are
    designed to help you access simple data (local/remote ip/port, protocol
    info, pointers to specific headers, etc.).

        key       contains local+remote ip and port, l3 and l4 protocol
        direction specifies if packet was inbound or outbound
        packet    wrapper the actual packet data, has length and packet data
    """
    pass

def main(args) :
    """
    Main routine.
    This is executed when the PNA detects a matching filter (e.g., if this
    is an 'http' monitor, an 'http' filter must be registered with the PNA:
    see service/filter for more details on registering a filter).
    The parameters that are handed to this program are defined by the pna,
    so you shouldn't have to deviate too much from this stub.
    """
    monitor = pna.PNA(args, hook=monitor_hook)
    monitor.monitor()

if __name__ == '__main__' :
    main(sys.argv)
