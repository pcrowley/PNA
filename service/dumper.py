#!/usr/bin/env python
# Helper program for converting a BPF expression into BPF VM code and
# delivering it to the kernel for execution.

import ctypes, struct, sys, os.path
from ctypes.util import find_library

proc_path = '/proc/pna'

dumper_add = os.path.join(proc_path, 'dumper_add')
dumper_del = os.path.join(proc_path, 'dumper_del')

if len(sys.argv) < 2 :
    print 'error: no filter name defined'
    sys.exit(1)
name = sys.argv[1]
expr = sys.argv[2:]

# This is a delete action, do that skip the rest
if name == '-d' :
    name = sys.argv[2]
    f = open(dumper_del, 'w')
    f.write('{0}'.format(name))
    f.close()
    print '{0} filter removed'.format(name)
    sys.exit(0)

# A bit of a sanity check to see if the filter already exists
if os.path.exists(os.path.join(proc_path, name)) :
    print '{0} filter exists'.format(name)
    sys.exit(1)

# struct bpf_insn {
#   u_short     code;
#   u_char      jt;
#   u_char      jf;
#   bpf_u_int32 k;
# };
class bpf_insn(ctypes.Structure):
    format = 'HBBI'
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]

# struct bpf_program {
#   u_int  bf_len;
#   struct bpf_insn *bf_insns;
# };
class bpf_program(ctypes.Structure):
    _fields_ = [
        ("bf_len", ctypes.c_int),
        ("bf_insns", ctypes.POINTER(bpf_insn)),
    ]

# get pcap library handle
pcap = ctypes.cdll.LoadLibrary(find_library('pcap'))
pcap_perror = pcap.pcap_perror

# pcap_t *pcap_open_dead(int linktype, int snaplen);
pcap_open_dead = pcap.pcap_open_dead

# void pcap_close(pcap_t *p);
pcap_close = pcap.pcap_close

# int pcap_compile(pcap_t *p, struct bpf_program *fp,
#                  const char *str, int optimize, bpf_u_int32 netmask);
pcap_compile = pcap.pcap_compile

# handy args
linktype = ctypes.c_int(1)   # Ethernet (10Mb)
snaplen = ctypes.c_int(0xffff)  # Ethernet max data length
optimize = ctypes.c_int(1)   # Optimization level
mask = ctypes.c_int(0)       # No netmask

# Open the pcap handler
pcap_handle = pcap_open_dead(linktype, snaplen)
if not pcap_handle :
    print 'error: could not open pcap handler'
    sys.exit(1)

# Create the filter reference
filter = ' '.join(expr)
filter_buf = ctypes.c_char_p(filter)

# Make a program instance and compile
program = bpf_program()
program_ref = ctypes.byref(program)
if -1 == pcap_compile(pcap_handle, program_ref, filter_buf, optimize, mask) :
    print 'error: could not compile program'
    pcap_perror(pcap_handle, ctypes.c_char_p(b'pcap'))
    sys.exit(2)

code = ''
for i in xrange(program.bf_len) :
    insn = program.bf_insns[i]
    code += struct.pack(insn.format, insn.code, insn.jt, insn.jf, insn.k)

f = open(dumper_add, 'w')
f.write('{0}\n'.format(name))
f.write(code)
f.close()

print '{0} filter installed ({1} instructions)'.format(name, program.bf_len)

pcap_close(pcap_handle)

