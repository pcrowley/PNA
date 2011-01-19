#!/usr/bin/env python

import sys, struct

__version__ = 'parse_0.1.0-py'

# This class simple parses a log file and returns a list of the raw data
# contained within that file.  It is up to the caller to convert that raw data
# into useful information
class PNALogParser :
    watch_entry_names = ('end-time','watch-data',)
    watch_data_names = ('local-ip', 'remote-ip',)
    watch_tuple_names = ('local-port', 'remote-port',
                        'npkts-in', 'npkts-out',
                        'nbytes-in', 'nbytes-out',
                        'begin-time', 'first-direction',)

    # log files may have some 0xffffffffs in the buffer, ignore those
    @classmethod
    def consume_filler(cls, data, start_pos, end_time, caller='unknown') :
        pos = start_pos
        while pos < len(data) :
            # consume one word at a time
            word = struct.unpack('I', data[pos:pos+4])[0]
            if word != 0xffffffff :
                skip = pos - start_pos
                if skip >= 4 and caller != 'lip' :
                    # it is possible this was port 65536:65536
                    # this is a bit hack-y since we fetch the direction and see
                    # if it is 'acceptable'
                    dir = struct.unpack('B', data[pos+24:pos+25])[0]
                    beg_time = struct.unpack('I', data[pos+20:pos+24])[0]
                    if dir >= 4 :
                        skip -= 4
                    # well, it also could be that the direction is
                    # acceptable...
                    # lets make sure the "begin_time" field is also
                    # acceptable
                    elif beg_time != 0 and not ((end_time - 30) <= beg_time <= (end_time + 30)) :
                        skip -= 4
                # we're done, say how much to skip
                #print 'consumed %d bytes (0x%08x)' % (skip, word)
                return skip
            pos += 4

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
                file_pos += cls.consume_filler(file_data, file_pos, end_time, 'lip')
                # now read in the watch_data
                sub_data = file_data[file_pos:file_pos+8]
                file_pos += 8
                data_values = struct.unpack('II', sub_data)
                data = dict(zip(cls.watch_data_names, data_values))

                # now read in the tcp port tuples
                tcp_tuples = []
                while True :
                    file_pos += cls.consume_filler(file_data, file_pos, end_time)
                    sub_data = file_data[file_pos:file_pos+28]
                    file_pos += 28
                    tuple_values = struct.unpack('HHIIIIIBxxx', sub_data)
                    if all(v==0 for v in tuple_values) :
                        break
                    tuple = dict(zip(cls.watch_tuple_names, tuple_values))
                    if tuple['first-direction'] == 0 :
                        file_pos -= 4
                        sub_data = file_data[file_pos-28:file_pos]
                        tuple_values = struct.unpack('HHIIIIIBxxx', sub_data)
                        tuple = dict(zip(cls.watch_tuple_names, tuple_values))
                    tcp_tuples.append(tuple)
                data['ntcp'] = len(tcp_tuples)

                # now read in the udp port tuples
                udp_tuples = []
                while True :
                    file_pos += cls.consume_filler(file_data, file_pos, end_time)
                    sub_data = file_data[file_pos:file_pos+28]
                    file_pos += 28
                    tuple_values = struct.unpack('HHIIIIIBxxx', sub_data)
                    if all(v==0 for v in tuple_values) :
                        break
                    tuple = dict(zip(cls.watch_tuple_names, tuple_values))
                    if tuple['first-direction'] == 0 :
                        file_pos -= 4
                        sub_data = file_data[file_pos-28:file_pos]
                        tuple_values = struct.unpack('HHIIIIIBxxx', sub_data)
                        tuple = dict(zip(cls.watch_tuple_names, tuple_values))
                    udp_tuples.append(tuple)
                data['nudp'] = len(udp_tuples)

                # finish up the watch_data structure
                data['tcp-tuples'] = tcp_tuples
                data['udp-tuples'] = udp_tuples

                # add source and destination port in the data
                #data['source-port'] = 
                #data['destination-port'] = 

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
