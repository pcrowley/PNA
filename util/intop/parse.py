#!/usr/bin/env python
#
# Copyright 2011 Washington University in St Louis
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys, struct

__version__ = 'parse_0.1.0-py'

# This class simple parses a log file and returns a list of the raw data
# contained within that file.  It is up to the caller to convert that raw data
# into useful information
class PNALogParser :
    v1hdr_fmt    = 'III'
    v1hdr_names  = ('start-time', 'end-time','size',)
    v1data_fmt   = 'IIHHIIIIIBBxx'
    v1data_names = ('local-ip', 'remote-ip',
                    'local-port', 'remote-port',
                    'packets-out', 'packets-in',
                    'bytes-out', 'bytes-in',
                    'begin-time', 'l4-protocol',
                    'first-direction',)

    v2hdr_fmt    = 'cccBIII'
    v2hdr_names  = ('magic0', 'magic1', 'magic2', 'version',
                    'start-time', 'end-time','size',)
    v2data_fmt   = 'HBxIIHHIIIIIIBBxx'
    v2data_names = ('l3-protocol', 'l4-protocol',
                    'local-ip', 'remote-ip',
                    'local-port', 'remote-port',
                    'bytes-out', 'bytes-in',
                    'packets-out', 'packets-in',
                    'end-time', 'begin-time',
                    'first-direction', 'flags',)

    def __init__(self) :
        self.clear_log()

    def get_log(self) :
        return self.log

    def clear_log(self) :
        self.log = { 'sessions': [] }

    def build_sessions(self, session) :
        self.log['sessions'].append(session)

    def parse_version(self, data, callback, version) :
        # grab formatting and name info
        hdr_fmt = getattr(self, version+'hdr_fmt')
        hdr_names = getattr(self, version+'hdr_names')
        data_fmt = getattr(self, version+'data_fmt')
        data_names = getattr(self, version+'data_names')

        # read the header data first
        pos = 0
        size = struct.calcsize(hdr_fmt)
        hdr_data = struct.unpack(hdr_fmt, data[pos:pos+size])
        pos += size
        self.log = dict(self.log.items() + zip(hdr_names, hdr_data))

        if not callback :
            callback = self.build_sessions

        # process the log data
        size = struct.calcsize(data_fmt)
        while pos < len(data) :
            # read an entry
            entry = struct.unpack(data_fmt, data[pos:pos+size])
            pos += size
            session = dict(zip(data_names, entry))
            if version == 'v1' :
                session['flags'] = 0
                session['end-time'] = self.log['start-time']
            callback(session)

    # read a log file and return the data as a python list
    def parse(self, file_name, session_callback=None) :
        # open the file up and get the data
        file_input = open(file_name, 'r')
        log_data = file_input.read()
        file_input.close()

        # Figure out what log version this is
        if log_data[0:3] != "PNA" :
            version = 'v1'
        else :
            version = 'v%d' % ord(log_data[3])

        self.parse_version(log_data, session_callback, version)

def main(argv) :
    if len(argv) < 2 :
        print 'version:', __version__
        print 'usage: %s <list of files>' % argv[0]
        sys.exit(1)

    parser = PNALogParser()
    for file in argv[1:] :
        parser.parse(file)
    print parser.get_sessions()

# start the program
if __name__ == '__main__' :
    main(sys.argv)
