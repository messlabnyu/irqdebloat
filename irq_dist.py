#!/usr/bin/python

import os
import sys
import json
import struct
import pprint

if len(sys.argv) < 3:
    print("Usage: ./irq_dist.py trace_dir ostag")

trace_dir = sys.argv[1]
ostag = sys.argv[2]

if ostag=="linux":
    # Linux
    bp = [0x806ae118, 0x806df590, 0x8054a274, 0x806325ec, 0x80640800, 0x8061d9f4, 0x8055efdc, 0x806a8520, 0x805953f4, 0x8010ff9c, 0x806dbc00, 0x806df250]
elif ostag=="linux_virt":
    bp = [0x8018730c, 0x80187fa8, 0x805cae28, 0x805d2c30, 0x805f7568, 0x8060e764, 0x8064be24, 0x806dd5a4, 0x806f2848, 0x807009ec, 0x8077374c, 0x80779b4c, 0x807a7100, 0x807aa5a8, 0x807aa8d0]
elif ostag=="freebsd":
    # FreeBSD
    bp = [0xc0140dbc, 0xc069a948, 0xc069a960, 0xc014fbb8, 0xc065c9d4, 0xc06410c4, 0xc06496b8]
elif ostag=="riscos":
    # RiscOS
    bp = [0xfc012ce0, 0x20049dbc, 0x20049e2c, 0x20049e9c, 0x20049f0c, 0x20049f7c, 0x20049fec, 0x2004a1ac, 0xfc207944, 0xfc2356c4, 0x200a38f4, 0xfc30742c, 0xfc2358b8, 0xfc1f58bc, 0xfc225910]
elif ostag=="beagle":
    bp=[0xc07aead0, 0xc07eb014, 0xc07ec9bc, 0xc0a9ac70, 0xc0b14630, 0xc0838e98, 0xc08600ac, 0xc091c078, 0xc09a2b7c, 0xc09c48d0, 0xc09c484c, 0xc0a46dbc, 0xc07e93d4, 0xc0a84284, 0xc0ad0f48, 0xc0b13834, 0xc082e3cc, 0xbf0f96dc, 0xc0afa66c]
elif ostag=="romulus":
    bp=[0x8058f92c, 0x8041d848, 0x804a0390, 0x8051da7c, 0x805466ec, 0x80530e68, 0x804453d0, 0x80510a70, 0x8040e5bc]
elif ostag=="sabre":
    bp=[0x8010f8f4, 0x8050aea8, 0x8050efac, 0x805119f0, 0x8051a168, 0x80541088, 0x8054527c, 0x8058d170, 0x806ff31c, 0x8070f284, 0x80715808, 0x807e9314, 0x8080cd94, 0x8085b414, 0x80894d54, 0x808c25a8, 0x808f7004, 0x80949f58, 0x8094b038, 0x8095e070, 0x80961b50, 0x809b186c, 0x809b97c8]
elif ostag=="vxwork":
    bp=[0x254400, 0x3806ec, 0x3dd474, 0x427fcc, 0x44bc48, 0x44ce80, 0x44eba4, 0x45046c, 0x5ba158, 0x60e360]
elif ostag=="nuri":
    bp=[0xc0019118, 0xc00191b4, 0xc001acdc, 0xc006bfa0, 0xc006c5e4, 0xc006c7a0, 0xc0146008, 0xc016fd7c, 0xc01a5700, 0xc01a58a0]


bpmap = {}
for x in bp:
    bpmap[x] = []

for d,_,files in os.walk(trace_dir):
    for fn in files:
        if not fn.startswith("trace_"):
            continue
        if fn.endswith(".pre"):
            continue
        trpath = os.path.join(d, fn)
        lines = []
        if fn.endswith(".pact"):
            with open(trpath, 'rb') as fd:
                data = fd.read()
            for i in range(8, len(data), 4):    # skip cpu modes
                lines.append(struct.unpack('<I',data[i:i+4])[0])
        else:
            with open(trpath, 'r') as fd:
                data = fd.read()
            for l in data.strip().split('\n')[1:]:
                if l.startswith("Stopped"):
                    break
                lines.append(int(l.split(':')[1].split(']')[0], 16))
        lcnt = 0
        for addr in lines:
            if addr in bpmap:
                bpmap[addr].append(lcnt)
            lcnt += 1

#pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(bpmap)
for x in bpmap:
    if bpmap[x]:
        print hex(x), min(bpmap[x]), max(bpmap[x]), float(sum(bpmap[x]))/len(bpmap[x]) if bpmap[x] else 0
    else:
        print hex(x), None

#with open(ostag+".json", 'w') as fd:
#    json.dump(bpmap, fd)
