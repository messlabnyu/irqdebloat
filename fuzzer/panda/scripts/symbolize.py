#!/usr/bin/env python

import subprocess
import sys

vmlinux = '/home/moyix/git/rpi/linux_dbg/vmlinux'

inf = open(sys.argv[1])
inf.readline()

addrs = set()
syms = {}

for line in inf:
    addrs.update(line.strip().split())
inf.close()

sym_output = subprocess.check_output(['addr2line', '-a', '-f', '-e', vmlinux] + list(addrs))
sym_output = sym_output.splitlines()
for i in range(0,len(sym_output),3):
    syms[sym_output[i]] = (sym_output[i+1],sym_output[i+2])

inf = open(sys.argv[1])
sys.stdout.write(inf.readline())
for line in inf:
    a,b = line.strip().split()
    a = '0x' + a
    b = '0x' + b
    print "%s (%s, %s) -> %s (%s, %s)" % (
        a, syms[a][0], syms[a][1].replace('/home/moyix/git/rpi/linux_dbg/',''),
        b, syms[b][0], syms[b][1].replace('/home/moyix/git/rpi/linux_dbg/','')
    )
