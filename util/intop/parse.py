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

    # read a log file and return the data as a python list
    @classmethod
    def parse(cls, file_name) :
        # read the file into a list
        file_input = open(file_name, 'r')
        log_data = file_input.read()
        file_input.close()

        # read the header data first
        pos = 0
        hdr_data = struct.unpack('III', log_data[pos:pos+12])
        pos += 12
        log = dict(zip(cls.pna_log_hdr_names, hdr_data))

        flows = []
        while pos < len(log_data) :
            # read an entry
            data = struct.unpack('IIHHIIIIIBBxx', log_data[pos:pos+36])
            pos += 36
            flow = dict(zip(cls.pna_log_data_names, data))
            flows.append(flow)

        log['flows'] = flows
        return log

def main(argv) :
    if len(argv) < 2 :
        print 'version:', __version__
        print 'usage: %s <list of files>' % argv[0]
        sys.exit(1)

    for file in argv[1:] :
        print PNALogParser.parse(file)

# start the program
if __name__ == '__main__' :
    main(sys.argv)
