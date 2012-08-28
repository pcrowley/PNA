#!/usr/bin/env python
"""
This is a stub file for creating custom python monitors for the PNA.
For an example implementation, see http_sniffer.py which uses this as the
base and creates a hook that snoops HTTP packets for matching strings.
"""

import pna, sys
import re, time

time_fmt = '%a, %d %b %Y %H:%M:%S'

supported_methods = ['GET', 'HEAD', 'PUT', 'POST']

regex_strs = [
    "^null$",\
    "/\.\./\.\./\.\./",\
    "\.\./\.\./config\.sys",\
    "/\.\./\.\./\.\./autoexec\.bat",\
    "/\.\./\.\./windows/user\.dat",\
    "\\\x02\\\xb1",\
    "\\\x04\\\x01",\
    "\\\x05\\\x01",\
    "\\\x90\\\x02\\\xb1\\\x02\\\xb1",\
    "\\\x90\\\x90\\\x90\\\x90",\
    "\\\xff\\\xff\\\xff\\\xff",\
    "\\\xe1\\\xcd\\\x80",\
    "\\\xff\xe0\\\xe8\\\xf8\\\xff\\\xff\\\xff-m",\
    "\\\xc7f\\\x0c",\
    "\\\x84o\\\x01",\
    "\\\x81",\
    "\\\xff\\\xe0\\\xe8",\
    "\/c\+dir",\
    "\/c\+dir\+c",\
    "\.htpasswd",\
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",\
    "author\.exe",\
    "boot\.ini",\
    "cmd\.exe",\
    "c%20dir%20c",\
    "default\.ida",\
    "fp30reg\.dll",\
    "httpodbc\.dll",\
    "nsiislog\.dll",\
    "passwd$",\
    "root\.exe",\
    "shtml\.exe",\
    "win\.ini",\
    "xxxxxxxxxxxxxxxxxxxxxx"
]

regex_list = [ re.compile(regex) for regex in regex_strs ]

def int_to_ip(ip) :
    return '.'.join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))

def alert(key, method, path, timestamp) :
    local_ip = int_to_ip(key['local_ip'])
    remote_ip = int_to_ip(key['remote_ip'])
    utc_time = time.strftime(time_fmt, time.gmtime(timestamp))
    local_time = time.strftime(time_fmt+' (%Z)', time.localtime(timestamp))

    print '-'*40
    print 'Someone has attempted a potentially dangerous access:'
    print '\tLocal Server: {0}'.format(local_ip)
    print '\t{0} Request: "{1}"'.format(method, path)
    print '\tRemote IP: {0}'.format(remote_ip)
    print '\tLocal Time: {0}'.format(local_time)
    print '\tUTC Time: {0}'.format(utc_time)
    sys.stdout.flush()

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
    if key['local_port'] != 80 or direction != pna.DIR_INBOUND :
        # Not interested in this packet
        return

    if packet.payload == None :
        # Everything is right, but no payload
        return

    # Okay, we've got a possible packet
    request = str(packet.payload).split('\r\n')[0]
    req_parts = request.split()
    if len(req_parts) != 3 :
        # This is not a recognized request
        return
    (method, path, version) = req_parts

    if method not in supported_methods :
        # Can't parse this
        return
    
    # Check if path matches any known regex
    for regex in regex_list :
        match = regex.search(path)
        if match :
            alert(key, method, path, packet.tv_sec)

def main(args) :
    """
    Main routine.
    This is executed when the PNA detects a matching filter (e.g., if this
    is an 'http' monitor, an 'http' filter must be registered with the PNA:
    see service/filter for more details on registering a filter).
    The parameters that are handed to this program are defined by the pna,
    so you shouldn't have to deviate too much from this stub.
    """
    monitor = pna.PNA(args, hook=monitor_hook, init=monitor_init)
    monitor.monitor()

if __name__ == '__main__' :
    main(sys.argv)
