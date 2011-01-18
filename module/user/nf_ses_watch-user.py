#!/usr/bin/env python

import sys, time, struct

proc_base = '/proc/nf_ses_watch'
log_dir = './logs'
file_fmt = log_dir + '/pna-%s-%s.log'
time_fmt = '%Y%m%d%H%M%S'
log_sleep = 10 # seconds
rotation_period = 0 # seconds

if len(sys.argv) != 2 :
    print 'usage: %s <tabid>' % ( sys.argv[0] )
    sys.exit(1)

tabid = sys.argv[1]

proc_file = proc_base+'/'+tabid
create_time = time.localtime(0)
current_time = time.localtime()
output = None

while True :
    if time.mktime(current_time) - time.mktime(create_time) > rotation_period :
        create_time = current_time
        logfile = file_fmt % (time.strftime(time_fmt, current_time), tabid)

    # fetch the procfile contents
    current_time = time.localtime()
    epoch_time = int(time.mktime(current_time))

    watch_file = open(proc_file, 'r')
    watch_contents = watch_file.read()
    watch_file.close()

    if len(watch_contents) > 0 :
        hdr = struct.pack('II', epoch_time, len(watch_contents))
        if output != sys.stdout :
            output = open(logfile, 'w')

        output.write(hdr)
        output.write(watch_contents)

        if output != sys.stdout :
            output.close()

    #size = 0
    #while True :
        #watch_contents = watch_file.read(4096)
        #if watch_contents == '' :
            #break
        # open of output file skipping header space
        #if size == 0 and len(watch_contents) > 0 :
            #output = open(logfile, 'w')
            #output.seek(8)

        #output.write(watch_contents)
        #size += len(watch_contents)

    # close the watch file
    #watch_file.close()

    # write header and close output file
    #if output != None :
        #hdr = struct.pack('II', epoch_time, size)
        #output.seek(0)
        #output.write(hdr)
        #output.close()
        #output = None

    time.sleep(log_sleep)
