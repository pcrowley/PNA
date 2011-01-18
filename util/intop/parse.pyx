#!/usr/bin/env python

import sys, struct

__version__ = 'parse_0.1.0-pyx'

# This class simple parses a log file and returns a list of the raw data
# contained within that file.  It is up to the caller to convert that raw data
# into useful information
class PNALogParser :
    watch_entry_names = ('end-time','watch-data',)
    watch_data_names = ('local-ip', 'remote-ip', 'ntcp', 'nudp',)
    watch_tuple_names = ('local-port', 'remote-port',
                        'npkts-in', 'npkts-out',
                        'nbytes-in', 'nbytes-out',
                        'begin-time', 'direction',)

    # read a log file and return the data as a python list
    @classmethod
    def parse(cls, file_name) :
        # read the file into a list
        file_input = open(file_name, 'r')
        file_data = file_input.read()
        file_input.close()

        file_pos = 0
        raw_data = [ ]

        while file_pos < len(file_data) :
            # read the header data first
            hdr = struct.unpack('II', file_data[file_pos:file_pos+8])
            file_pos += 8
            end_time = hdr[0]
            entry_length = hdr[1]
            entry = dict(zip(cls.watch_entry_names, (end_time, [])))

            entry_pos = file_pos
            while file_pos < entry_pos + entry_length :
                # now read in the watch_data
                sub_data = file_data[file_pos:file_pos+16]
                file_pos += 16
                data_values = struct.unpack('IIII', sub_data)
                data = dict(zip(cls.watch_data_names, data_values))

                # now read in the tcp port tuples
                tcp_tuples = []
                while len(tcp_tuples) < data['ntcp'] :
                    sub_data = file_data[file_pos:file_pos+28]
                    file_pos += 28
                    tuple_values = struct.unpack('HHIIIIIBxxx', sub_data)
                    tuple = dict(zip(cls.watch_tuple_names, tuple_values))
                    tcp_tuples.append(tuple)

                # now read in the udp port tuples
                udp_tuples = []
                while len(udp_tuples) < data['nudp'] :
                    sub_data = file_data[file_pos:file_pos+28]
                    file_pos += 28
                    tuple_values = struct.unpack('HHIIIIIBxxx', sub_data)
                    tuple = dict(zip(cls.watch_tuple_names, tuple_values))
                    udp_tuples.append(tuple)

                # finish up the watch_data structure
                data['tcp-tuples'] = tcp_tuples
                data['udp-tuples'] = udp_tuples

                # add it to the data dictionary
                entry['watch-data'].append(data)
            raw_data.append(entry)
        return raw_data

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
