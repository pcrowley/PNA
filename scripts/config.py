#!/usr/bin/env python

import struct 
from optparse import OptionParser
import sys, socket

# The position in the array determines the type passed to nf_ses_watch
cfg_params = [ 'connections',
               'tcp-ports', 'udp-ports', 'all-ports',
               'tcp-bytes', 'udp-bytes', 'all-bytes',
               'tcp-packets', 'udp-packets', 'all-packets',
               'sessions', 'net_prefix', 'net_mask', ]

PROCFILE = "/proc/nf_ses_watch/config"

# add options for command line parsing
usage = 'usage: %prog --(get|set) PARAM [<value>]\n'
usage += 'PARAM is one of:\n\t'+('\n\t'.join(cfg_params))
usage += '\nDuring a --get operation, the PARAM "all" can also be used'

p = OptionParser(usage=usage)
p.add_option('--get', action='store_true', dest='get', metavar='PARAM',
			 help='get PARAM from nf_ses_watch')
p.add_option('--set', action='store_false', dest='get', metavar='PARAM',
			 help='set PARAM in nf_ses_watch')

# parse for get/set
(options, args) = p.parse_args()

if options.get == None or len(args) < 1 :
	p.print_help()
	sys.exit(1)

param = args.pop(0)
try :
	param_index = cfg_params.index(param)
except ValueError :
	if param == 'all' :
		# read from proc file and dump thresholds
		f = open(PROCFILE, 'r')
		data = f.read(len(cfg_params)*8)
		f.close()
		for i in range(len(cfg_params)) :
			begin = i * 8
			end = begin + 8
			xchg = struct.unpack('II', data[begin:end])
			print cfg_params[i], 'is %u (0x%08x)' % (xchg[1], xchg[1])
		sys.exit(0)
	else :
		p.print_help()
		sys.exit(1)

if param not in cfg_params :
	p.print_help()
	sys.exit(1)

if options.get == True :
	# read from proc file and dump thresholds
	f = open(PROCFILE, 'r')
	data = f.read(len(cfg_params)*8)
	f.close()
	begin = param_index * 8
	end = begin + 8
	xchg = struct.unpack('II', data[begin:end])

	print param, 'at index', param_index, 'is %u (0x%08x)' % (xchg[1], xchg[1])
elif options.get == False :
	if len(args) < 1 :
		p.print_help()
		sys.exit(1)
	value = original = args.pop(0)
	if len(value.split('.')) == 4 :
		value = socket.inet_aton(value)
		value = struct.unpack('I', value)[0]
		value = socket.htonl(value)
	elif value[0:2] == '0x' :
		value = int(value, 16)
	else :
		value = int(value)

	# write to procfile
	f = open(PROCFILE, 'wb')
	xchg = struct.pack('II', param_index, value)
	f.write(xchg)
	f.close()

	print 'set',param,'at index',param_index,'to', original
