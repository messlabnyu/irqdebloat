#!/bin/python

import os
import re
import json
import itertools

DIFFOUT_DIR = "/data/tonyhu/irq/log/raspi_diff"
#DIFFOUT_DIR = "/data/tonyhu/irq/log/subdiff"

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
    print hex(int(d)), " : ", [hex(e) for e in t]#, " - ", [t for t in diverge_trace[d]]


tracedir = "/data/tonyhu/irq/log/raspi_trace"
#tracedir = "/data/tonyhu/irq/log/subtrace"

iovals = {}
for curdir,_,traces in os.walk(tracedir):
    for tr in traces:
        if not tr.startswith("iovals_"):
            continue
        pat = re.compile("iovals_([0-9]*).log")
        trid = pat.match(tr).groups()[0]
        with open(os.path.join(tracedir, tr), 'r') as fd:
            iolog = fd.read().split('\n')[0]
            ioval = iolog.split("val=")[1]
            iovals[trid] = int(ioval, 16)

from diffslice import DiffSliceAnalyzer

anal = DiffSliceAnalyzer()

tracelog = {}
for curdir,_,traces in os.walk(tracedir):
    for trace in traces:
        tr = os.path.abspath(os.path.join(tracedir, trace))
        if not tr.endswith(".pre"):
            continue
        with open(tr, 'r') as fd:
            tracelog[tr] = json.load(fd)['trace']

ARM_CPU_MODE_IRQ = 0x12
ARM_CPU_MODE_SVC = 0x13
rawtrace = {}   # undedupped trace
for curdir,_,traces in os.walk(tracedir):
    for trace in traces:
        if not trace.startswith("trace_"):
            continue
        if trace.endswith(".pre"):
            continue

        idx = trace.split('_')[-1].split('.')[0]
        tr = os.path.abspath(os.path.join(tracedir, trace))
        with open(tr, 'r') as fd:
            data = fd.read().strip()
        modeline = data.split('\n')[0]
        m = modeline.split()
        prev_mode = int(m[-1], 16)
        cur_mode = int(m[2][:-1], 16)
        if not (cur_mode == ARM_CPU_MODE_SVC and prev_mode == ARM_CPU_MODE_IRQ):
            continue
        lines = data.split('\n')[1:]    # skip the 1st line
        rawtrace[idx] = []
        for l in lines:
            # TODO: ignore Data Abt? or truncate trace here?
            if l.startswith("Stopped"):
                continue
            addr = int(l.split(':')[1].split(']')[0], 16)
            # skip exception vector stub
            if addr&0xffff0000 == 0xffff0000:
                continue
            rawtrace[idx].append(addr)

diverge_appearance = {}
target_appearance = {}
diverge_eistack = {}
for tr_x,tr_y in itertools.combinations(tracelog, 2):

    per_diverge_appearance = {}

    idx = int(tr_x.split('_')[-1].split('.')[0])
    idy = int(tr_y.split('_')[-1].split('.')[0])
    diverge, _, _, eistack = anal.diff(None,
            {'trace': tracelog[tr_x], 'id': idx},
            {'trace': tracelog[tr_y], 'id': idy},
            True)

    # per trace frequency count
    for d in diverge:
        if d not in per_diverge_appearance:
            per_diverge_appearance[d] = 0
        per_diverge_appearance[d] += 1

    for d, ei in zip(diverge, eistack):
        if d not in diverge_appearance:
            diverge_appearance[d] = [0, 0, 9999999999, len(diverge_trace[str(d)]), 0, 9999999999]
        diverge_appearance[d][0] += 1   # total appearance
        diverge_appearance[d][1] = max(diverge_appearance[d][1], per_diverge_appearance[d]) # max appearance per trace
        diverge_appearance[d][2] = min(diverge_appearance[d][1], per_diverge_appearance[d]) # min appearance per trace
        diverge_appearance[d][4] = max(diverge_appearance[d][4],
                len([x for x in rawtrace[str(idx)] if x == d]),
                len([x for x in rawtrace[str(idy)] if x == d]))     # max appearance in un-dedup trace
        diverge_appearance[d][5] = min(diverge_appearance[d][5],
                len([x for x in rawtrace[str(idx)] if x == d]),
                len([x for x in rawtrace[str(idy)] if x == d]))     # min appearance in un-dedup trace
        if d not in diverge_eistack:
            diverge_eistack[d] = [0, 0]
        diverge_eistack[d][0] = max(diverge_eistack[d][0], len(eistack))
        diverge_eistack[d][1] += len(eistack)

for x, y in diverge_eistack.iteritems():
    mx = 0
    mi = 9999999999
    for t in rawtrace:
        mi = min(mi, len([r for r in rawtrace[t] if r == x]))    # max appearance across all un-dedup traces
        mx = max(mx, len([r for r in rawtrace[t] if r == x]))    # min appearance across all un-dedup traces
    print hex(x), " : ", y, " appear: ", diverge_appearance[x], ": ", float(y[1])/diverge_appearance[x][3], \
            "raw appear: ", [mi, mx]
    print "targets: ", [hex(t) for t in diverge_targets[str(x)]]
    for t in diverge_targets[str(x)]:
        mx = 0
        mi = 9999999999
        for rt in rawtrace:
            mi = min(mi, len([r for r in rawtrace[rt] if r == t]))
            mx = max(mx, len([r for r in rawtrace[rt] if r == t]))
        print "    ", hex(t), " : ", [mi, mx]

