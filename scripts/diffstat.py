#!/usr/bin/python

import os
import re
import sys
import json
import itertools

DIFFOUT_DIR = "/data/tonyhu/irq/log/raspi_diff"
DIFFOUT_DIR = "/data/tonyhu/irq/log/linux_enum_l1_diff"
DIFFOUT_DIR = "/data/tonyhu/irq/log/riscpi_enum_l1_diff"
DIFFOUT_DIR = "/data/tonyhu/irq/log/freebsd_enum_l1_diff"
DIFFOUT_DIR = sys.argv[4]
#DIFFOUT_DIR = "/data/tonyhu/irq/log/testdiff"


from analysis import *

anal = DiffSliceAnalyzer()
bv = anal.rawmem_bn_init(regfile, memfile)
mmap = anal.mm.walk()

def getva(pa):
    va = None
    for v, p, sz, _ in mmap:
        if pa&(~(sz-1)) == p-anal.mm.cpu._physical_mem_base:
            #assert (not va)
            va = v+(pa&(sz-1))
    return va

if ostag=="linux":
    # Linux
    bp = [0x806ae118, 0x806df590, 0x8054a274, 0x806325ec, 0x80640800, 0x8061d9f4, 0x8055efdc, 0x806a8520, 0x805953f4, 0x8010ff9c, 0x806dbc00, 0x806df250]
elif ostag=="freebsd":
    # FreeBSD
    bp = [0xc0140dbc, 0xc069a948, 0xc069a960, 0xc014fbb8, 0xc065c9d4, 0xc06410c4, 0xc06496b8]
elif ostag == "riscos":
    # RiscOS
    bp = [0xfc012ce0, 0x20049dbc, 0x20049e2c, 0x20049e9c, 0x20049f0c, 0x20049f7c, 0x20049fec, 0x2004a1ac, 0xfc207944, 0xfc2356c4, 0x200a38f4, 0xfc30742c, 0xfc2358b8, 0xfc1f58bc, 0xfc225910]
elif ostag == "beagle":
    bp = [0xc07aead0, 0xc07eb014, 0xc07ec9bc, 0xc0a9ac70, 0xc0b14630, 0xc0838e98, 0xc08600ac, 0xc091c078, 0xc09a2b7c, 0xc09c48d0, 0xc09c484c, 0xc0a46dbc, 0xc07e93d4, 0xc0a84284, 0xc0ad0f48, 0xc0b13834, 0xc082e3cc, 0xbf0f96dc, 0xc0afa66c]
elif ostag == "romulus":
    bp = [0x8058f92c, 0x8041d848, 0x804a0390, 0x8051da7c, 0x805466ec, 0x80530e68, 0x804453d0, 0x80510a70, 0x8040e5bc]

pbp = [anal.mm.translate(v) - anal.mm.cpu._physical_mem_base for v in bp]

ddlist = [DIFFOUT_DIR]
if ostag == "linux" and "linux_enum_gpu_2_diff" == os.path.basename(os.path.normpath(DIFFOUT_DIR)):
    ddlist.append(os.path.join(os.path.dirname(os.path.normpath(DIFFOUT_DIR)), "linux_enum_l1_diff"))
elif ostag == "linux" and "linux_enum_l1_diff" == os.path.basename(os.path.normpath(DIFFOUT_DIR)):
    ddlist.append(os.path.join(os.path.dirname(os.path.normpath(DIFFOUT_DIR)), "linux_enum_gpu_2_diff"))
diverge_targets = {}
diverge_trace = {}
addrstat = {}
difflog = {}
cnt = 0
for dd in ddlist:
    for d,_,files in os.walk(dd):
        for fn in files:
            if fn.startswith("diverge_"):
                pat = re.compile("diverge_([0-9]*)_([0-9]*).json")
                x, y = pat.match(fn).groups()
                with open(os.path.join(d, fn), 'r') as fd:
                    ix = min(int(x), int(y)) + cnt*10000000
                    iy = max(int(x), int(y)) + cnt*10000000
                    jd = json.load(fd)
                if ix not in difflog:
                    difflog[ix] = {}
                # trace pair should be unique
                assert(iy not in difflog[ix])
                #if iy not in difflog[ix]:
                #    difflog[ix][iy] = []
                diverges = [int(e[0]) for e in jd['diverge']]
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
    cnt += 1

dts = set()
for x in diverge_targets:
    dts.update(diverge_targets[x])
for p in pbp:
    print("DEBUG", hex(p))
    if p in dts:
        print(hex(p))

for addr, cnt in addrstat.items():
    print hex(addr), " : ", cnt

tracestat = {}
for x in difflog:
    for y in difflog[x]:
        key = str(set([hex(e) for e in difflog[x][y]]))
        if key not in tracestat:
            tracestat[key] = 0
        tracestat[key] += 1
#for tp, cnt in tracestat.items():
#    print tp, " : ", cnt
for d, t in diverge_targets.items():
    print hex(int(d)), hex(getva(int(d))), " : ", [hex(e)+"("+hex(getva(e))+")" for e in t], " - ", len([t for t in diverge_trace[d]])

print("diverge point#: ", len(diverge_targets))
print("diverge target#: ", len(dts))
sys.exit()

tracedir = "/data/tonyhu/irq/log/raspi_trace"
tracedir = "/data/tonyhu/irq/log/linux_enum_l1"
tracedir = "/data/tonyhu/irq/log/riscpi_enum_l1"
tracedir = "/data/tonyhu/irq/log/freebsd_enum_l1"
tracedir = sys.argv[1]

#iovals = {}
#for curdir,_,traces in os.walk(tracedir):
#    for tr in traces:
#        if not tr.startswith("iovals_"):
#            continue
#        pat = re.compile("iovals_([0-9]*).log")
#        trid = pat.match(tr).groups()[0]
#        with open(os.path.join(tracedir, tr), 'r') as fd:
#            iolog = fd.read().split('\n')[0]
#            ioval = iolog.split("val=")[1]
#            iovals[trid] = int(ioval, 16)


tracedirlist = [tracedir]
if ostag == "linux" and "linux_enum_gpu_2" == os.path.basename(os.path.normpath(tracedir)):
    tracedirlist.append(os.path.join(os.path.dirname(os.path.normpath(tracedir)), "linux_enum_l1"))
elif ostag == "linux" and "linux_enum_l1" == os.path.basename(os.path.normpath(tracedir)):
    tracedirlist.append(os.path.join(os.path.dirname(os.path.normpath(tracedir)), "linux_enum_gpu_2"))

diverge_appearance = {}
target_appearance = {}
diverge_eistack = {}

cnt = 0
for trd in tracedirlist:
    tracelog = {}
    for curdir,_,traces in os.walk(trd):
        for trace in traces:
            tr = os.path.abspath(os.path.join(trd, trace))
            if not tr.endswith(".pre"):
                continue
            with open(tr, 'r') as fd:
                tracelog[tr] = json.load(fd)['trace']

    #rawtrace = {}   # undedupped trace
    #for curdir,_,traces in os.walk(trd):
    #    for trace in traces:
    #        if not trace.startswith("trace_"):
    #            continue
    #        if trace.endswith(".pre"):
    #            continue

    #        idx = trace.split('_')[-1].split('.')[0]
    #        tr = os.path.abspath(os.path.join(trd, trace))
    #        with open(tr, 'r') as fd:
    #            if not check_status(fd.readline(), ostag):
    #                continue
    #        rawtrace[idx] = [anal.mm.translate(x) for x in parse_trace(tr, False, False)]

    for tr_x,tr_y in itertools.combinations(tracelog, 2):
        print tr_x, tr_y

        per_diverge_appearance = {}

        idx = int(tr_x.split('_')[-1].split('.')[0])
        idy = int(tr_y.split('_')[-1].split('.')[0])
        diverge, _, _, eistack = anal.diff(None,
                {'trace': tracelog[tr_x], 'id': idx},
                {'trace': tracelog[tr_y], 'id': idy},
                True)

        # per trace frequency count
        #for dp in diverge:
        #    assert (dp[0] == dp[1])
        #    d = dp[0]
        #    if d not in per_diverge_appearance:
        #        per_diverge_appearance[d] = 0
        #    per_diverge_appearance[d] += 1

        for dp, ei in zip(diverge, eistack):
            assert (dp[0] == dp[1])
            d = dp[0]
            #if d not in diverge_appearance:
            #    diverge_appearance[d] = [0, 0, 9999999999, len(diverge_trace[str(d)]) if str(d) in diverge_trace else 1, 0, 9999999999]
            #diverge_appearance[d][0] += 1   # total appearance
            #diverge_appearance[d][1] = max(diverge_appearance[d][1], per_diverge_appearance[d]) # max appearance per trace
            #diverge_appearance[d][2] = min(diverge_appearance[d][1], per_diverge_appearance[d]) # min appearance per trace
            #diverge_appearance[d][4] = max(diverge_appearance[d][4],
            #        len([x for x in rawtrace[str(idx)] if x == d]),
            #        len([x for x in rawtrace[str(idy)] if x == d]))     # max appearance in un-dedup trace
            #diverge_appearance[d][5] = min(diverge_appearance[d][5],
            #        len([x for x in rawtrace[str(idx)] if x == d]),
            #        len([x for x in rawtrace[str(idy)] if x == d]))     # min appearance in un-dedup trace
            if d not in diverge_eistack:
                diverge_eistack[d] = [0, 0, 0]
            diverge_eistack[d][0] = max(diverge_eistack[d][0], len(eistack))
            diverge_eistack[d][1] += len(eistack)
            diverge_eistack[d][2] += 1
    cnt += 1

lst = []
for x, y in diverge_eistack.iteritems():
    lst.append([x, y[0], float(y[1])/y[2]])
    #mx = 0
    #mi = 9999999999
    #for t in rawtrace:
    #    mi = min(mi, len([r for r in rawtrace[t] if r == x]))    # max appearance across all un-dedup traces
    #    mx = max(mx, len([r for r in rawtrace[t] if r == x]))    # min appearance across all un-dedup traces
    #print hex(x), " : ", y, " appear: ", diverge_appearance[x], ": ", float(y[1])/diverge_appearance[x][3], \
    #        "raw appear: ", [mi, mx]
    #if str(x) in diverge_targets:
    #    print "targets: ", [hex(t) for t in diverge_targets[str(x)]]
    #    for t in diverge_targets[str(x)]:
    #        mx = 0
    #        mi = 9999999999
    #        for rt in rawtrace:
    #            mi = min(mi, len([r for r in rawtrace[rt] if r == t]))
    #            mx = max(mx, len([r for r in rawtrace[rt] if r == t]))
    #        print "    ", hex(t), " : ", [mi, mx]
lst.sort(key=lambda x:x[2])
for x,y,z in lst:
    print hex(x), y, " - ", z
