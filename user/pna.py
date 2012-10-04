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

DEFAULT_LOG_DIR = './logs'
DIR_OUTBOUND = 0
DIR_INBOUND = 1

class Packet :
    fields = 'HBxIIHH' + 'IIII' + 'iLLLL'
    key_names = ('l3_protocol', 'l4_protocol', 'local_ip',
                 'remote_ip', 'local_port', 'remote_port')
    names = key_names + ('eth_addr', 'ip_addr', 'l4_addr', 'payload_addr',
            'direction', 'tv_sec', 'tv_usec', 'len', 'caplen')
    field_size = struct.calcsize(fields)

    def __init__(self, packet) :
        values = struct.unpack(self.fields, packet[0:self.field_size])
        d = dict(zip(self.names, values))
        self.__dict__.update(d)
        self.key = {}
        for name in self.key_names :
            self.key[name] = getattr(self, name)
            delattr(self, name)
        self.data = None
        self.eth_hdr = None
        self.ip_hdr = None
        self.l4_hdr = self.udp_hdr = self.tcp_hdr = None
        self.payload = None

    def set_data(self, data) :
        self.data = data

        if self.ip_addr > self.eth_addr :
            self.eth_hdr = self.data[self.eth_addr:self.ip_addr]
        else :
            self.eth_hdr = self.data[self.eth_addr:]

        if self.l4_addr > self.ip_addr :
            self.ip_hdr = self.data[self.ip_addr:self.l4_addr]
        else :
            self.ip_hdr = self.data[self.ip_addr:]

        if self.payload_addr > self.l4_addr :
            self.l4_hdr = self.data[self.l4_addr:self.payload_addr]
        else :
            self.l4_hdr = self.data[self.l4_addr:]

        if self.payload_addr != 0 :
            self.payload = self.data[self.payload_addr:]

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
        self.proc_file = args[0]
        self.verbose = opts.verbose
        self.log_dir = opts.log_dir

        if self.verbose :
            print 'running {0} with {1}'.format(self.prog_name, self.proc_file)
            sys.stdout.flush()

    def monitor(self) :
        # call the monitor initialization routine
        if self.init :
            self.init()

        # open the procfile for reading
        with open(self.proc_file, 'r') as procfile :
            # as long as the procfile doesn't send EOF, keep reading
            while True :
                # Python is a bit weird, get just the header bytes
                bytes = procfile.read(Packet.field_size)
                if len(bytes) <= 0 :
                    break

                # Parse the header bytes
                pkt = Packet(bytes)
                # Now get the remaining bytes (should be packet data)
                pkt.set_data(procfile.read(pkt.caplen))
                sys.stdout.flush()

                # call the monitor hook function with params
                if self.hook:
                    self.hook(pkt.key, pkt.direction, pkt);


        # call any monitor release routines
        if self.release :
            self.release()
