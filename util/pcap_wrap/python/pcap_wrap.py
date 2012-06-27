#!/usr/bin/env python
# This python script allows quick prototyping of potential PNA hooks.
# It takes PCAP files as input, does some preliminary work on a packet
# (getting it setup similarly to how it would be passed by the PNA).
# The only thing you should need to write is the monitor_hook() function
# and any helpers you need associated with it.

import sys
import socket
import struct
import pycap
import pycap.capture as capture
import pycap.constants as constants

PNA_PREFIX = '128.252.0.0'
PNA_MASK = '255.255.0.0'
PNA_DIR_OUTBOUND = 0
PNA_DIR_INBOUND = 1

def monitor_hook(key, direction, pkt, data) :
    packet = explode_pkt(pkt)
    print key
    print packet

def explode_pkt(pkt) :
    # Assume we start with an Ethernet header
    eth_end = 14
    eth_hdr = pkt[0:eth_end]
    eth_type = struct.unpack('>H', eth_hdr[12:14])[0]
    if eth_type != constants.ethernet.ETHERTYPE_IP :
        return (eth_hdr,)

    # We've got an IP packet, break off the IP layer
    ip_end = eth_end + 4*(ord(pkt[eth_end]) & 0x0f)
    ip_hdr = pkt[eth_end:ip_end]
    ip_proto = ord(ip_hdr[9])
    if ip_proto not in (constants.ip.IPPROTO_TCP, constants.ip.IPPROTO_UDP) :
        return (eth_hdr, ip_hdr,)

    if ip_proto == constants.ip.IPPROTO_TCP :
        # We've got a TCP header, break off the TCP layer
        hdr_end = ip_end + 4*(ord(pkt[ip_end+12]) >> 4)
        last_hdr = pkt[ip_end:hdr_end]
    elif ip_proto == constants.ip.IPPROTO_UDP :
        # We've got a UDP header, break off the UDP layer
        hdr_end = ip_end + 8
        last_hdr = pkt[ip_end:hdr_end]

    if len(pkt) <= hdr_end :
        return (eth_hdr, ip_hdr, last_hdr,)

    # Return the layers of the packet
    payload = pkt[hdr_end:]
    return (eth_hdr, ip_hdr, last_hdr, payload,)

##
# Shouldn't need to change things below this point
##

def ip2int(addr) :
    ip = 0x00000000
    o = addr.split('.')
    ip |= (int(o[0]) << 24)
    ip |= (int(o[1]) << 16)
    ip |= (int(o[2]) << 8)
    ip |= (int(o[3]) << 0)
    return ip

def int2ip(addr) :
    octet = (addr>>24&0xff, addr>>16&0xff, addr>>8&0xff, addr&0xff)
    return '.'.join([ str(o) for o in octet ])

pkt_count = 0

def pna_callback(pkt) :
    global pkt_count
    pkt_count += 1
    key = {'l3_protocol':0, 'l4_protocol':0, 'local_ip':0, 'remote_ip':0,
           'local_port':0, 'remote_port':0}
    direction = -1
    data = -1

    # Lets just assume everything is Ethernet
    type = socket.ntohs(pkt[0].type)
    if type != constants.ethernet.ETHERTYPE_IP :
        return
    key['l3_protocol'] = type
    bin_pkt = pkt[0].packet

    # Make sure it is recognized TCP or UDP
    proto = pkt[1].protocol
    if proto not in (constants.ip.IPPROTO_TCP, constants.ip.IPPROTO_UDP) :
        return
    key['l4_protocol'] = proto
    src_ip = pkt[1].source
    dst_ip = pkt[1].destination
    bin_pkt += pkt[1].packet

    # Extract l4 info
    src_pt = pkt[2].sourceport
    dst_pt = pkt[2].destinationport
    bin_pkt += pkt[2].packet

    # Localize
    temp = ip2int(src_ip) & ip2int(PNA_MASK)
    if temp == (ip2int(PNA_PREFIX) & ip2int(PNA_MASK)) :
        # src_ip is local
        key['local_ip'] = ip2int(src_ip)
        key['remote_ip'] = ip2int(dst_ip)
        key['local_port'] = src_pt
        key['remote_port'] = dst_pt
        direction = PNA_DIR_OUTBOUND
    else :
        # dst_ip is local
        key['local_ip'] = ip2int(dst_ip)
        key['remote_ip'] = ip2int(src_ip)
        key['local_port'] = dst_pt
        key['remote_port'] = src_pt
        direction = PNA_DIR_INBOUND
    bin_pkt += pkt[3]

    # Pass to montior
    monitor_hook(key, direction, bin_pkt, data)
 
def main(file) :
    try :
        cap = capture.capture.fromFile(file)
        while True :
            pkt = cap.next()
            if not pkt :
                break
            pna_callback(pkt)
    except KeyboardInterrupt :
        print ' detected, shutting down'
    except capture.error :
        pass
    print 'Processed {} packets'.format(pkt_count)

if __name__ == '__main__' :
    if len(sys.argv) != 2 :
        print 'usage: {} <pcapfile>'.format(sys.argv[0])
        exit(1)
    main(sys.argv[1])
