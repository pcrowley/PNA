"""
This is a glue file. It binds the underlying PNA technology to a user
written monitor. It should require no modification, just import this
python module and call pna.main() and pna.monitor().  See example_mon.py
for usage.

There is also support for:
 - C (pna.c)
"""

import os
import struct
import optparse

import sys

# These are set by the PNA node, but should be emulated here
PNA_PREFIX = '128.252.0.0'
PNA_MASK = '255.255.0.0'

DEFAULT_LOG_DIR = './logs'
DIR_OUTBOUND = 0
DIR_INBOUND = 1

def ip2int(ip) :
    ip1, ip2, ip3, ip4 = ip.split('.')
    s = int(ip1) * 2**24
    s += int(ip2) * 2**16
    s += int(ip3) * 2**8
    s += int(ip4)
    return s

PNA_PREFIX = ip2int(PNA_PREFIX)
PNA_MASK = ip2int(PNA_MASK)

class Packet :
    hdr_fields = 'IHHiIII'
    fields = 'iiII'
    key_names = ('l3_protocol', 'l4_protocol', 'local_ip',
                 'remote_ip', 'local_port', 'remote_port')
    #names = ('magic', 'version_major', 'version_minor', 'thiszone',
    #         'sigfigs', 'snaplen', 'linktype')
    names = ('tv_sec', 'tv_usec', 'caplen', 'len')
    field_size = struct.calcsize(fields)
    header_size = struct.calcsize(hdr_fields)

    def __init__(self, packet) :
        values = struct.unpack(self.fields, packet[0:self.field_size])
        d = dict(zip(self.names, values))
        self.__dict__.update(d)
        self.key = {}
        for name in self.key_names :
            self.key[name] = 0
        self.length = self.caplen + self.field_size
        self.data = None
        self.eth_hdr = None
        self.ip_hdr = None
        self.l4_hdr = self.udp_hdr = self.tcp_hdr = None
        self.payload = None
        self.direction = None

    def set_data(self, data) :
        self.data = data
        # Some constants
        ETHERTYPE_IP = 0x0800
        IPPROTO_TCP = 6
        IPPROTO_UDP = 17

        # Assume we start with an Ethernet header
        eth_end = 14
        self.eth_hdr = self.data[0:eth_end]
        eth_type = struct.unpack('>H', self.eth_hdr[12:14])[0]
        if eth_type != ETHERTYPE_IP :
            return
        self.key['l3_protocol'] = ETHERTYPE_IP

        # We've got an IP packet, break off the IP layer
        ip_end = eth_end + 4*(ord(self.data[eth_end]) & 0x0f)
        self.ip_hdr = self.data[eth_end:ip_end]
        ip_proto = ord(self.ip_hdr[9])
        if ip_proto not in (IPPROTO_TCP, IPPROTO_UDP) :
            return

        if ip_proto == IPPROTO_TCP :
            # We've got a TCP header, break off the TCP layer
            hdr_end = ip_end + 4*(ord(self.data[ip_end+12]) >> 4)
            self.l4_hdr = self.data[ip_end:hdr_end]
            self.key['l4_protocol'] = IPPROTO_TCP
        elif ip_proto == IPPROTO_UDP :
            # We've got a UDP header, break off the UDP layer
            hdr_end = ip_end + 8
            self.l4_hdr = self.data[ip_end:hdr_end]
            self.key['l4_protocol'] = IPPROTO_UDP
        self.udp_hdr = self.tcp_hdr = self.l4_hdr

        src_ip = '.'.join(str(ord(b)) for b in self.ip_hdr[12:16])
        dst_ip = '.'.join(str(ord(b)) for b in self.ip_hdr[16:20])
        src_pt = struct.unpack('>H', self.l4_hdr[0:2])[0]
        dst_pt =  struct.unpack('>H', self.l4_hdr[2:4])[0]
        temp = ip2int(src_ip) & PNA_MASK
        if temp == (PNA_PREFIX & PNA_MASK) :
            # src_ip is local
            self.key['local_ip'] = ip2int(src_ip)
            self.key['remote_ip'] = ip2int(dst_ip)
            self.key['local_port'] = src_pt
            self.key['remote_port'] = dst_pt
            self.direction = DIR_OUTBOUND
        else :
            # dst_ip is local
            self.key['local_ip'] = ip2int(dst_ip)
            self.key['remote_ip'] = ip2int(src_ip)
            self.key['local_port'] = dst_pt
            self.key['remote_port'] = src_pt
            self.direction = DIR_INBOUND

        if len(self.data) <= hdr_end :
            return

        # Return the layers of the packet
        self.payload = self.data[hdr_end:]
        return

class PNA :
    def __init__(self, args, init=None, release=None, hook=None) :
        self.init = init
        self.release = release
        self.hook = hook

        self.prog_name = args[0]

        # process any arguments
        parser = optparse.OptionParser(prog=self.prog_name)

        parser.add_option('-d', '--dir', dest='log_dir', help='save logs to LOG_DIR', metavar='LOG_DIR', default=DEFAULT_LOG_DIR)
        parser.add_option('-v','--verbose', dest='verbose', action='store_true', help='verbose mode', default=False);
        parser.add_option('-e','--exec-dir', dest='exec_dir', help='(ignored)', default=False);

        opts, args = parser.parse_args()
        self.input_file = args[0]
        self.verbose = opts.verbose
        self.log_dir = opts.log_dir

        if self.verbose :
            print 'running {0} with {1}'.format(self.prog_name, self.input_file)
            sys.stdout.flush()

    def monitor(self) :
        # call the monitor initialization routine
        if self.init :
            self.init()

        # open the inputfile for reading
        with open(self.input_file, 'r') as inputfile :
            # as long as the inputfile doesn't send EOF, keep reading
            inputfile.seek(Packet.header_size)
            while True :
                # Python is a bit weird, get just the header bytes
                bytes = inputfile.read(Packet.field_size)
                if len(bytes) <= 0 :
                    break

                # Parse the header bytes
                pkt = Packet(bytes)
                # Now get the remaining bytes (should be packet data)
                pkt.set_data(inputfile.read(pkt.length - pkt.field_size))

                # call the monitor hook function with params
                if self.hook:
                    self.hook(pkt.key, pkt.direction, pkt);


        # call any monitor release routines
        if self.release :
            self.release()
