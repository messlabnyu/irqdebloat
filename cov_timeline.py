#!/usr/bin/env python

import time
import argparse
import struct
import os, glob
import sys

reasons = {
    0: 'REASON_TIMEOUT',
    1: 'REASON_MAXBLOCKS',
    2: 'REASON_ABORT',
    3: 'REASON_NOCOV',
}
reasons.update({v:k for k,v in reasons.items()})
kinds = {
    0: 'BLOCK',
    1: 'IO_READ',
    2: 'IO_WRITE',
    3: 'EXIT'
}
kinds.update({v:k for k,v in kinds.items()})

#dt = np.dtype([
#    ('kind',np.uint32),
#    ('pc',np.uint32),
#    ('addr',np.uint32),
#    ('val',np.uint32),
#    ])

parser = argparse.ArgumentParser(description='Display when handlers were found chronologically')
parser.add_argument('-f', '--first', action="store_true", help='only consider the first handler found in a trace')
parser.add_argument('handlers', help='file containing handler addresses and names, one per line')
parser.add_argument('tracedir', help='directory containing btrace files')
args = parser.parse_args()

handler_sym = {}
for line in open(args.handlers):
    addr, sym = line.strip().split()
    handler_sym[int(addr,16)] = sym

handlers = set(handler_sym.keys())
files = glob.glob(os.path.join(args.tracedir, '*.btrace'))
files.sort(key=os.path.getmtime)
for f in files:
    #data = np.fromfile(f,dtype=dt)
    with open(f, 'rb') as fd:
        data = fd.read()
    for i in range(0, len(data), 16):
        kind = struct.unpack('<I', data[i:i+4])[0]
        pc = struct.unpack('<I', data[i+4:i+8])[0]
        if kind == 0 and pc in handlers:
            filetime = time.ctime(os.path.getmtime(f))
            print(f"{pc:08x} ({handler_sym[pc]:<30s}) found at {filetime} in block {i} of {os.path.basename(f)}")
            handlers -= set([pc])
            if args.first: break
    if not handlers: break
for h in handlers:
    print(f"{h:08x} ({handler_sym[h]}) never found")
