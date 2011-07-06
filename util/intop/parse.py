#!/usr/bin/env python

import sys, struct

__version__ = 'parse_0.1.0-py'

# This class simple parses a log file and returns a list of the raw data
# contained within that file.  It is up to the caller to convert that raw data
# into useful information
class PNALogParser :
    pna_log_hdr_names = ('start-time', 'end-time','size',)
    pna_log_data_names = ('local-ip', 'remote-ip',
                          'local-port', 'remote-port',
                          'packets-out', 'packets-in',
                          'bytes-out', 'bytes-in',
                          'begin-time', 'protocol',
                          'first-direction',)
    record = 'IIHHIIIIIBBxx'
    record_size = 36

    def __init__(self) :
        self.clear_log()

    def get_log(self) :
        return self.log

    def clear_log(self) :
        self.log = { 'flows': [] }

    def build_flows(self, flow) :
        self.log['flows'].append(flow)

    # read a log file and return the data as a python list
    def parse(self, file_name, flow_callback=None) :
        # open the file for reading
        input = open(file_name, 'r')
        in_data = input.read()
        input.close()
        pos = 0

        # read the header data first
        hdr_data = struct.unpack('III', in_data[pos:pos+12])
        pos += 12
        self.log = dict(self.log.items() + zip(self.pna_log_hdr_names, hdr_data))
        if not flow_callback :
            flow_callback = self.build_flows

        while pos < len(in_data) :
            # read an entry
            data = struct.unpack(self.record, in_data[pos:pos+self.record_size])
            pos += self.record_size
            flow = dict(zip(self.pna_log_data_names, data))
            flow['end-time'] = self.log['start-time']
            flow_callback(flow)

def main(argv) :
    if len(argv) < 2 :
        print 'version:', __version__
        print 'usage: %s <list of files>' % argv[0]
        sys.exit(1)

    parser = PNALogParser()
    for file in argv[1:] :
        parser.parse(file)
    print parser.get_flows()

# start the program
if __name__ == '__main__' :
    main(sys.argv)
