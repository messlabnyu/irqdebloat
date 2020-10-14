#!/bin/python

import os
import re
import json

DIFFOUT_DIR = "/data/tonyhu/irq/log/diffout"

diverge_targets = {}
diverge_trace = {}
addrstat = {}
difflog = {}
for d,_,files in os.walk(DIFFOUT_DIR):
    for fn in files:
        if fn.startswith("diverge_"):
            pat = re.compile("diverge_([0-9]*)_([0-9]*).json")
            x, y = pat.match(fn).groups()
            with open(os.path.join(d, fn), 'r') as fd:
                ix = min(int(x), int(y))
                iy = max(int(x), int(y))
                jd = json.load(fd)
            if ix not in difflog:
                difflog[ix] = {}
            # trace pair should be unique
            assert(iy not in difflog[ix])
            #if iy not in difflog[ix]:
            #    difflog[ix][iy] = []
            diverges = [int(e) for e in jd['diverge']]
            difflog[ix][iy] = [e for e in diverges]

            for k in jd['target']:
                if k not in diverge_targets:
                    diverge_targets[k] = set()
                diverge_targets[k].update(jd['target'][k])
                if k not in diverge_trace:
                    diverge_trace[k] = set()
                diverge_trace[k].update([ix, iy])

            for addr in set(diverges):
                if addr not in addrstat:
                    addrstat[addr] = 0
                addrstat[addr] += 1

for addr, cnt in addrstat.items():
    print hex(addr), " : ", cnt

tracestat = {}
for x in difflog:
    for y in difflog[x]:
        key = str(set([hex(e) for e in difflog[x][y]]))
        if key not in tracestat:
            tracestat[key] = 0
        tracestat[key] += 1
for tp, cnt in tracestat.items():
    print tp, " : ", cnt
for d, t in diverge_targets.items():
    print hex(int(d)), " : ", [hex(e) for e in t], " - ", [t for t in diverge_trace[d]]
