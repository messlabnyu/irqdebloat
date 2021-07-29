#!/usr/bin/python

import os
import re
import sys
import json
import math
import pprint

#ddlist = ["/data/tonyhu/irq/log/linux_enum_l1_diff", "/data/tonyhu/irq/log/linux_enum_gpu_2_diff"]
#trlist = ["/data/tonyhu/irq/log/linux_enum_l1", "/data/tonyhu/irq/log/linux_enum_gpu_2"]
#ddlist = ["/data/tonyhu/irq/log/freebsd_enum_gpu_diff", "/data/tonyhu/irq/log/freebsd_enum_l1_diff"]
#trlist = ["/data/tonyhu/irq/log/freebsd_enum_gpu", "/data/tonyhu/irq/log/freebsd_enum_l1"]
#ddlist = ["/data/tonyhu/irq/log/beagle_enum_gpu_2_diff"]
#trlist = ["/data/tonyhu/irq/log/beagle_enum_gpu_2"]

#from analysis import DiffSliceAnalyzer
from analysis import *
from extract_postdominators import get_return_blocks

if ostag=="linux":
    # Linux
    bp = [0x806ae118, 0x806df590, 0x8054a274, 0x806325ec, 0x80640800, 0x8061d9f4, 0x8055efdc, 0x806a8520, 0x805953f4, 0x8010ff9c, 0x806dbc00, 0x806df250]
elif ostag=="linux_virt":
    bp = [0x8018730c, 0x80187fa8, 0x805cae28, 0x805d2c30, 0x805f7568, 0x8060e764, 0x8064be24, 0x806dd5a4, 0x806f2848, 0x807009ec, 0x8077374c, 0x80779b4c, 0x807a7100, 0x807aa5a8, 0x807aa8d0]
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
elif ostag=="sabre":
    bp=[0x8010f8f4, 0x8050aea8, 0x8050efac, 0x805119f0, 0x8051a168, 0x80541088, 0x8054527c, 0x8058d170, 0x806ff31c, 0x8070f284, 0x80715808, 0x807e9314, 0x8080cd94, 0x8085b414, 0x80894d54, 0x808c25a8, 0x808f7004, 0x80949f58, 0x8094b038, 0x8095e070, 0x80961b50, 0x809b186c, 0x809b97c8]
elif ostag=="vxwork":
    bp=[0x254400, 0x3806ec, 0x3dd474, 0x427fcc, 0x44bc48, 0x44ce80, 0x44eba4, 0x45046c, 0x5ba158, 0x60e360]
elif ostag=="nuri":
    bp=[0xc0019118, 0xc00191b4, 0xc001acdc, 0xc006bfa0, 0xc006c5e4, 0xc006c7a0, 0xc0146008, 0xc016fd7c, 0xc01a5700, 0xc01a58a0]
else:
    bp=[]

if ostag == "wrt":
    arch = "mipsel32"
else:
    arch = "armv7"

anal = DiffSliceAnalyzer()
bv = anal.rawmem_bn_init(regfile, memfile, get_membase(ostag), arch)
trlist = [tracedir]
ddlist = [outdir]
#bv = anal.rawmem_bn_init("/data/tonyhu/irq/irq_fuzzer/snapshots/freebsd.reg", "/data/tonyhu/irq/irq_fuzzer/snapshots/freebsd.mem")
#bv = anal.rawmem_bn_init("/data/tonyhu/irq/irq_fuzzer/snapshots/irqdebloat_groundtruth/beaglebone/beaglebone.reg", "/data/tonyhu/irq/irq_fuzzer/snapshots/beaglebone.mem")
mmap = anal.mm.walk()

def getva(pa):
    va = []
    for v, p, sz, _ in mmap:
        if pa&(~(sz-1)) == p-anal.mm.cpu._physical_mem_base:
            #assert (not va)
            va.append(v+(pa&(sz-1)))
    #assert(va)
    return va

def check_indbr(bv,pa):
    retry = 2
    for idx in range(21):
        i = bv.get_disassembly(pa+idx*4)
        if not i:
            retry -= 1
            if retry > 0:
                continue
            return -1
        i = i.split()
        if len(i) < 2:
            continue
        mnemonic = i[0]
        op = "".join(i[1:])
        if bv.arch.name == 'armv7':
            if mnemonic in ["blx","bx", "bl"] and op.startswith("0x"):
                # skip any direct call before indirect call
                break
            elif mnemonic in ["blx","bx"] and op.startswith("r"):
                #print hex(dp), ":", [hex(x) for x in diverge_targets[d]]
                return idx
            elif mnemonic == "ldm" and not op.startswith("sp") and not op.startswith("r13") and "pc}" in op:
                return idx
            #elif i.mnemonic.startswith("b") and not i.mnemonic.startswith("bic"):
            elif mnemonic == "b":
                break
            elif mnemonic == "ldm" and (op.startswith("sp") or op.startswith("r13")) and "pc}" in op:
                break
            elif mnemonic == "ldr" and op.startswith("pc,"):
                break
            elif mnemonic == "bx" and op == "lr":
                break
        elif bv.arch.name == 'mipsel32':
            if mnemonic in ["jr", "jalr"] and not op.startswith("$ra"):
                return idx
    return -1

diverge_targets = {}
for dd in ddlist:
    for d,_,files in os.walk(dd):
        for fn in files:
            if fn.startswith("diverge_"):
                pat = re.compile("diverge_([0-9a-f]*)_([0-9a-f]*).json")
                x, y = pat.match(fn).groups()
                with open(os.path.join(d, fn), 'r') as fd:
                    ix = min(x, y)
                    iy = max(x, y)
                    jd = json.load(fd)

                for k in jd['target']:
                    if k not in diverge_targets:
                        diverge_targets[k] = set()
                    diverge_targets[k].update(jd['target'][k])

glob_indbr = {}
bpmap = {}
for x in diverge_targets:
    #print(x, [hex(a) for a in diverge_targets[x]])
    bpmap[int(x)] = []

raw_traces = {}
for trace_dir in trlist:
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
                    if not l.startswith("Trace"):
                        continue
                    lines.append(int(l.split(':')[1].split(']')[0],16))
            lcnt = 0
            raw_traces[trpath] = []
            for i,l in enumerate(lines):
                raw_traces[trpath].append(l)
                addr = anal.mm.translate(l) - anal.mm.cpu._physical_mem_base
                if i+1 < len(lines):
                    next_addr = anal.mm.translate(lines[i+1]) - anal.mm.cpu._physical_mem_base
                else:
                    next_addr = None
                if addr not in glob_indbr:
                    if next_addr:
                        glob_indbr[addr] = set([next_addr])
                else:
                    if next_addr:
                        glob_indbr[addr].add(next_addr)
                if addr in bpmap:
                    bpmap[addr].append(lcnt)
                lcnt += 1

glob_functions = set()
for fp,trace in raw_traces.items():
    return_blocks = {}
    grouped_traces, raw_trace = get_return_blocks(return_blocks, bv, raw_trace={'full_trace': trace}, vm=anal.mm)
    glob_functions.update([f.start for f in grouped_traces.keys()])
    #glob_functions.update([grouped_traces[f][0][0] for f in grouped_traces.keys()])

# All Indirect Calls
gindlist = [k for k in glob_indbr.keys()]
gindlist.sort(reverse=True)
seen_ind = set()
for x in gindlist:
    idx = check_indbr(bv, x)
    if idx == -1:
        glob_indbr.pop(x)
        continue
    sec = seen_ind.intersection([x+4*si for si in range(idx+1)])
    if not sec:
        seen_ind.add(x)
    else:
        assert(len(sec)==1)
        v = glob_indbr.pop(x)
        glob_indbr[sec.pop()].update(v)
print("all indirect calls: ", len(glob_indbr))
#for x in glob_indbr:
#    print hex(x), [hex(d) for d in glob_indbr[x] if d in glob_functions]

# Div Points Indirect Calls
pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(bpmap)
sl = []
divlist = [k for k in bpmap.keys()]
divlist.sort(reverse=True)
seen_ind = set()
for x in divlist:
    idx = check_indbr(bv,x)
    if idx == -1:
        continue
    if not seen_ind.intersection([x+4*si for si in range(idx+1)]):
        tgs = [hex(d) for d in diverge_targets[str(x)] if d in glob_functions]
        if len(tgs)>1:      # Make sure to have more than One target
            sl.append((x, float(sum(bpmap[x]))/len(bpmap[x]) if bpmap[x] else 0))
            seen_ind.add(x)
print("indirct call in divergence points: ", len(sl))
print("all divergence points: ", len(diverge_targets))
alltargets = set()
sl.sort(key=lambda x: x[1])
for x,y in sl:
    # Original Diff result (contains divergence points in inferred shadow basic blocks)
    tgs = set([d for d in diverge_targets[str(x)] if d in glob_functions])
    alltargets.update([d for d in diverge_targets[str(x)] if d in glob_functions])
    if x in glob_indbr:
        divp = x
    else:
        divp = min([d for d in glob_indbr if d >= x])
    # Update from real traces which contains Shared IRQ handlers
    tgs.update([d for d in glob_indbr[divp] if d in glob_functions])
    alltargets.update([d for d in glob_indbr[divp] if d in glob_functions])
    if tgs:
        if len(bpmap[x]) > 1:
            print(hex(x), [hex(va) for va in getva(x)], y, math.sqrt(sum([(c-y)**2 for c in bpmap[x]])/(len(bpmap[x])-1)), [(hex(tg), [hex(va) for va in getva(tg)]) for tg in tgs])
        else:
            print(hex(x), [hex(va) for va in getva(x)], y, 0, [(hex(tg), [hex(va) for va in getva(tg)]) for tg in tgs])

#print [[hex(va) for va in getva(int(x))] for x in diverge_targets.keys()]
pbp = [anal.mm.translate(v) - anal.mm.cpu._physical_mem_base for v in bp]
for p in pbp:
    print("DEBUG", hex(p))
    if p in alltargets:
        print(hex(p))
print("False Positives: ", [(hex(d), [hex(va) for va in getva(d)]) for d in alltargets if d not in pbp])
