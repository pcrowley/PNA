#!/usr/bin/env python
"""
This is a stub file for creating custom python monitors for the PNA.
For an example implementation, see http_sniffer.py which uses this as the
base and creates a hook that snoops HTTP packets for matching strings.
"""

import pna, sys
import time
import pprint

supported_methods = ['GET', 'HEAD', 'PUT', 'POST']

bad_request = 0
bad_method = 0
bad_header = 0
http_bytes = 0
total_bytes = 0
start = None
end = None

def monitor_init() :
    """
    Initialization routines for your monitor.
    Allocate any global resources or initial values here.
    """
    global bad_request, bad_method, bad_header, http_bytes, total_bytes, start, end
    bad_request = 0
    bad_method = 0
    bad_header = 0
    http_bytes = 0
    total_bytes = 0
    start = time.time()

def monitor_release() :
    """
    Release routines for your monitor.
    Free up or write out any remaining data you may have, the program is
    exiting.
    """
    global bad_request, bad_method, bad_header, http_bytes, total_bytes, start, end
    end = time.time()
    print bad_request, bad_method, bad_header
    print http_bytes, total_bytes
    print start, end, end-start
    print 'HTTP Mb/s:', (http_bytes*8/1E6) / (end-start)
    print 'Total Mb/s:', (total_bytes*8/1E6) / (end-start)

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
    global bad_request, bad_method, bad_header, http_bytes, total_bytes
    total_bytes += packet.len

    if key['local_port'] != 80 or direction != pna.DIR_INBOUND :
        # Not interested in this packet
        return

    if packet.payload == None :
        # Everything is right, but no payload
        return

    http_bytes += packet.len

    # Okay, we've got a possible packet
    request = str(packet.payload).split('\r\n')
    try :
        (method, path, version) = request[0].split()
    except ValueError :
        bad_request += 1
        return

    if method not in supported_methods :
        bad_method += 1
        return

    http = {method: path, 'Protocol-Version':version}
    for line in request[1:] :
        try :
            (field, value) = line.split(':', 1)
            http[field.strip()] = value.strip()
        except ValueError :
            pass
    try:
        if request[-1] != request[-2] :
            bad_header += 1
    except IndexError :
        bad_header += 1

    #pprint.pprint(http)

def main(args) :
    """
    Main routine.
    This is executed when the PNA detects a matching filter (e.g., if this
    is an 'http' monitor, an 'http' filter must be registered with the PNA:
    see service/filter for more details on registering a filter).
    The parameters that are handed to this program are defined by the pna,
    so you shouldn't have to deviate too much from this stub.
    """
    monitor = pna.PNA(args, hook=monitor_hook, init=monitor_init,
            release=monitor_release)
    monitor.monitor()

if __name__ == '__main__' :
    main(sys.argv)
