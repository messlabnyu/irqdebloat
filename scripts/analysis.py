import os
import re
import sys
import hashlib
import itertools
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
    if mode in ['linux', 'freebsd', 'beagle', 'romulus']:
        return (cur_mode == ARM_CPU_MODE_SVC and prev_mode == ARM_CPU_MODE_IRQ)
    else:   # RiscOS
        return cur_mode == ARM_CPU_MODE_IRQ

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
        if tag == "linux" and addr == 0x8051da68:
            break
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


def preproc_traces():
    # use simple hash to deduplicate traces
    trace_buckets = dict()
    for curdir,_,traces in os.walk(tracedir):
        for tr in traces:
            if not tr.startswith("trace_"):
                continue
            if tr.endswith(".pre"):
                continue
            trpath = os.path.join(curdir, tr)
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
        traces.append({'dir': tf, 'full_trace': parse_trace(tf, ostag)})
    return traces

def debugdiff():
    traces = preproc_traces()
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
    traces = preproc_traces()
    anal = DiffSliceAnalyzer()
    bv = anal.bn_init(kernelfile)
    anal.bn_analyze(bv, traces, outdir)

def diff_rawmem():
    anal = DiffSliceAnalyzer()
    bv = anal.rawmem_bn_init(regfile, memfile)

    traces = preproc_traces()
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

if __name__ == "__main__":
    #debugdiff()
    #diff()
    diff_rawmem()
