import os
import re
import sys
import json
import time
import struct
import hashlib
import itertools
import multiprocessing
from string import Formatter

from diffslice import DiffSliceAnalyzer


ARM_CPU_MODE_USR = 0x10
ARM_CPU_MODE_FIQ = 0x11
ARM_CPU_MODE_IRQ = 0x12
ARM_CPU_MODE_SVC = 0x13
ARM_CPU_MODE_MON = 0x16
ARM_CPU_MODE_ABT = 0x17
ARM_CPU_MODE_HYP = 0x1a
ARM_CPU_MODE_UND = 0x1b
ARM_CPU_MODE_SYS = 0x1f

class TraceBucket(object):
    def __init__(self, tr=None):
        self.traces = set([tr]) if tr else set()
    def update(self, newtr):
        self.traces.add(newtr)
    def count(self):
        return len(self.traces)
    def getone(self):
        return next(iter(self.traces))

def check_status(line, mode='linux'):
    l = line.split()
    prev_mode = int(l[-1], 16)
    cur_mode = int(l[2][:-1], 16)
    if mode in ['linux', 'freebsd', 'beagle', 'romulus', 'sabre', 'vxwork']:
        return (cur_mode == ARM_CPU_MODE_SVC and prev_mode == ARM_CPU_MODE_IRQ)
    else:   # RiscOS
        return cur_mode == ARM_CPU_MODE_IRQ

def parse_compact_trace(tracefile, tag, tracelimit=True):
    trace = []
    with open(tracefile, 'rb') as fd:
        data = fd.read()
    for i in range(8, len(data), 4):
        addr = struct.unpack('<I', data[i:i+4])[0]
        if tag == "freebsd" and addr == 0xc069bd84:
            break
        # skip exception vector stub
        if addr&0xffff0000 == 0xffff0000:
            continue
        trace.append(addr)

        #if tracelimit and len(trace) > 20000:
        #    break
    return trace

def parse_trace(tracefile, tag, dedup=True, tracelimit=True):
    with open(tracefile, 'r') as fd:
        data = fd.read().strip()
    lines = data.split('\n')[1:]    # skip the 1st line
    trace = []
    for l in lines:
        # Note: ignore Data Abt? or truncate trace here?
        if l.startswith("Stopped"):
            break

        addr = int(l.split(':')[1].split(']')[0], 16)
        # FreeBSD irq hack: truncate at the end of first intc dispatch loop
        if tag == "freebsd" and addr == 0xc069bd84:
            break
        #if tag == "linux" and addr == 0x8051da68:
        #    break
        # skip exception vector stub
        if addr&0xffff0000 == 0xffff0000:
            continue
        # deduplicate loop trace
        if dedup and trace and addr == trace[-1]:
            continue

        trace.append(addr)

        if tracelimit and len(trace) > 20000:
            break
    return trace


if len(sys.argv) < 6:
    print("Usage: ./analysis.py tracedir regfile memfile outdir ostag")
    sys.exit()

tracedir = "../log/trace"
tracedir = "../log/raspi_trace"
tracedir = "../log/subtrace"
tracedir = "../log/irq8_trace"
tracedir = "../log/linux_enum_l1"
tracedir = "../log/riscpi_enum_l1"
tracedir = "../log/freebsd_enum_l1"
tracedir = sys.argv[1]

#kernelfile = "../log/home/moyix/bbb/build/tmp/work/beaglebone-poky-linux-gnueabi/linux-stable/5.7.14-r0/build/vmlinux"
#kernelfile = "../instrument/vmlinux"
#kernelfile = "../log/rpi2_linux/vmlinux"
regfile = "snapshots/raspi2.reg"
memfile = "snapshots/raspi2.mem"
regfile = "snapshots/riscpi.reg"
memfile = "snapshots/riscpi.mem"
regfile = "snapshots/freebsd.reg"
memfile = "snapshots/freebsd.mem"
regfile = sys.argv[2]
memfile = sys.argv[3]

outdir = "../log/diffout"
outdir = "../log/raspi_diff"
outdir = "../log/subdiff"
outdir = "../log/irq8_diff"
outdir = "../log/linux_enum_l1_diff"
outdir = "../log/riscpi_enum_l1_diff"
outdir = "../log/freebsd_enum_l1_diff"
outdir = sys.argv[4]
#outdir = "../log/testdiff"
#tracedir = "../log/testsub"

ostag = "linux"
ostag = "riscos"
ostag = "freebsd"
ostag = sys.argv[5]


def preproc_traces(trdirs):
    # use simple hash to deduplicate traces
    trace_buckets = dict()
    for tdir in trdirs:
        for curdir,_,traces in os.walk(tdir):
            for tr in traces:
                if not tr.startswith("trace_"):
                    continue
                if tr.endswith(".pre"):
                    continue
                trpath = os.path.join(curdir, tr)
                if tr.endswith(".pact"):
                    with open(trpath, 'rb') as fd:
                        normtr = fd.read()
                else:
                    with open(trpath, 'r') as fd:
                        if not check_status(fd.readline(), ostag):
                            continue
                        # normalize qemu trace log
                        normtr = re.sub("Trace 0x[0-9a-f]*", "Trace ", fd.read())
                        # skip invalid traces
                        if "Stopped execution of TB chain" in normtr:
                            continue
                tag = hashlib.sha1(normtr).hexdigest()
                if tag in trace_buckets:
                    trace_buckets[tag].update(trpath)
                else:
                    trace_buckets[tag] = TraceBucket(trpath)

    for h,tb in trace_buckets.iteritems():
        if tb.count()>1:
            print(h)
            print(tb.traces)
    print(len(trace_buckets))

    tracefiles = [trace_buckets[f].getone() for f in trace_buckets.keys()]
    #tracefiles = ["../log/trace/trace_13.log", "../log/trace/trace_347.log"]
    #tracefiles = ["../log/trace/trace_93.log", "../log/trace/trace_347.log"]
    #tracefiles = ["../log/trace/trace_93.log", "../log/trace/trace_361.log"]
    #tracefiles = ["../log/trace/trace_93.log", "../log/trace/trace_1.log"]

    traces = []
    for tf in tracefiles:
        if tf.endswith(".pact"):
            traces.append({'dir': tf, 'full_trace': parse_compact_trace(tf, ostag)})
        else:
            traces.append({'dir': tf, 'full_trace': parse_trace(tf, ostag)})
    return traces

def debugdiff():
    traces = preproc_traces([tracedir])
    done_combo = set()
    if os.path.exists(os.path.join(outdir, "done.log")):
        with open(os.path.join(outdir, "done.log"), 'r') as fd:
            done_combo = set(fd.read().strip().split('\n'))

    anal = DiffSliceAnalyzer()
    bv = anal.bn_init(kernelfile)
    for tr_x,tr_y in itertools.combinations(traces, 2):

        key = tr_x['dir']+tr_y['dir']
        if key in done_combo or (tr_y['dir']+tr_x['dir']) in done_combo:
            continue
        done_combo.add(key)

        anal.bn_analyze(bv, [tr_x, tr_y], outdir)
        with open(os.path.join(outdir, "done.log"), 'w') as fd:
            fd.write("\n".join(done_combo))

def diff():
    traces = preproc_traces([tracedir])
    anal = DiffSliceAnalyzer()
    bv = anal.bn_init(kernelfile)
    anal.bn_analyze(bv, traces, outdir)

def diff_rawmem(membase=0):
    anal = DiffSliceAnalyzer()
    bv = anal.rawmem_bn_init(regfile, memfile, membase)

    traces = preproc_traces([tracedir])
    ## Truncate traces at user space address
    #vmap = {}
    #for va, pa, sz, prot in anal.mm.walk():
    #    assert (va not in vmap)
    #    vmap[va] = prot
    #for tr in traces:
    #    newtr = []
    #    for va in tr['full_trace']:
    #        vpg = va&(~anal.mm.page_mask(va))
    #        # make sure non-writeable from lower PL (RiscOS fixes)
    #        if not vmap[vpg].check_write_pl0():
    #            newtr.append(va)
    #        else:
    #            break
    #    tr['full_trace'] = [x for x in newtr]

    anal.bn_analyze(bv, traces, outdir)

def anal_mc(reg, mem, tr, out, membase):
    anal = DiffSliceAnalyzer()
    bv = anal.rawmem_bn_init(reg, mem, membase)
    anal.bn_analyze(bv, tr, out, mcore=True)

def diffhand_mc(tracepairs, out):
    anal = DiffSliceAnalyzer()
    for tr_x, tr_y in tracepairs:
        diverge_points = set()
        branch_targets = set()
        final_traces = {}

        for tr in [tr_x, tr_y]:
            with open("{}.pre".format(tr), 'r') as fd:
                final_traces[tr] = json.load(fd)['trace']

        if final_traces[tr_x][0][0] != final_traces[tr_y][0][0]:
            continue

        idx = tr_x.split('_')[-1].split('.')[0]
        idy = tr_y.split('_')[-1].split('.')[0]
        diverge, aligned, targets, _ = anal.diff(
                out,
                {'trace': final_traces[tr_x], 'id': idx},
                {'trace': final_traces[tr_y], 'id': idy})
        diverge_points.difference_update(diverge)
        branch_targets.update(targets)

        with open(os.path.join(out, "diverge_{}_{}.json".format(idx, idy)), 'w') as fd:
            jout = {'diverge': [pt for pt in diverge_points], 'target': {}}
            for xl in branch_targets:
                if xl[0] not in jout['target']:
                    jout['target'][xl[0]] = []
                jout['target'][xl[0]] = [e for e in set(list(xl[1:]) + jout['target'][xl[0]])]
            json.dump(jout, fd)


def diff_mc(membase=0):
    tracewc = []
    for r,ds,_ in os.walk(tracedir):
        tracewc.extend([os.path.join(r,d) for d in ds])
    if not tracewc:
        tracewc = [tracedir]

    traces = preproc_traces(tracewc)

    NPROC = 16
    traces_list = [[] for i in range(NPROC)]
    outs = []
    for i in range(NPROC):
        subpath = os.path.join(os.path.normpath(outdir), "diff_"+str(i))
        if not os.path.exists(subpath):
            os.makedirs(subpath)
        outs.append(subpath)
    for i, tr in enumerate(traces):
        traces_list[i%NPROC].append({'dir': tr['dir'], 'full_trace': [t for t in tr['full_trace']]})

    # preprocess
    pool = [multiprocessing.Process(target=anal_mc, args=(regfile, memfile, traces_list[i], outs[i], membase)) \
            for i in range(NPROC)]
    map(lambda x: x.start(), pool)
    while True in map(lambda x: x.is_alive(), pool):
        time.sleep(60)
        print "Prep: ", map(lambda x: x.is_alive(), pool)

    # collect preprocess log
    diffdir = os.path.join(os.path.normpath(outdir), "diff")
    if not os.path.exists(diffdir):
        os.makedirs(diffdir)
    preplog = {'traces': []}
    for o in outs:
        with open(os.path.join(o, "preprocessed.log"), 'r') as fd:
            data = json.load(fd)
        preplog['traces'].extend(data['traces'])
    with open(os.path.join(diffdir, "preprocessed.log"), 'w') as fd:
        json.dump(preplog, fd)

    # diff
    diffsets = [[] for i in range(NPROC)]
    counter = 0
    for tr_x, tr_y in itertools.combinations(preplog['traces'], 2):
        diffsets[counter%NPROC].append((tr_x, tr_y))
        counter += 1
    pool = [multiprocessing.Process(target=diffhand_mc, args=(diffsets[i], diffdir)) for i in range(NPROC)]
    map(lambda x: x.start(), pool)
    while True in map(lambda x: x.is_alive(), pool):
        time.sleep(60)
        print "Diff: ", map(lambda x: x.is_alive(), pool)

def get_membase(tag):
    if tag in ["beagle", "romulus"]:
        return 0x80000000
    if tag in ["sabre", "vxwork"]:
        return 0x10000000
    if tag == "nuri":
        return 0x40000000
    return 0

if __name__ == "__main__":
    #debugdiff()
    #diff()
    membase = get_membase(ostag)
    #diff_rawmem(membase)
    diff_mc(membase)
