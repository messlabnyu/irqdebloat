import os
import re
import sys
import hashlib
from string import Formatter

from diffslice import DiffSliceAnalyzer

tracedir = "../log/trace"

ARM_CPU_MODE_USR = 0x10
ARM_CPU_MODE_FIQ = 0x11
ARM_CPU_MODE_IRQ = 0x12
ARM_CPU_MODE_SVC = 0x13
ARM_CPU_MODE_MON = 0x16
ARM_CPU_MODE_ABT = 0x17
ARM_CPU_MODE_HYP = 0x1a
ARM_CPU_MODE_UND = 0x1b
ARM_CPU_MODE_SYS = 0x1f

def check_status(line):
    l = line.split()
    prev_mode = int(l[-1], 16)
    cur_mode = int(l[2][:-1], 16)
    return (cur_mode == ARM_CPU_MODE_SVC and prev_mode == ARM_CPU_MODE_IRQ)

class TraceBucket(object):
    def __init__(self, tr=None):
        self.traces = set([tr]) if tr else set()
    def update(self, newtr):
        self.traces.add(newtr)
    def count(self):
        return len(self.traces)
    def getone(self):
        return next(iter(self.traces))

# use simple hash to deduplicate traces
trace_buckets = dict()
for curdir,_,traces in os.walk(tracedir):
    for tr in traces:
        trpath = os.path.join(curdir, tr)
        with open(trpath, 'r') as fd:
            if not check_status(fd.readline()):
                continue
            # normalize qemu trace log
            normtr = re.sub("Trace 0x[0-9a-f]*", "Trace ", fd.read())
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

def parse_trace(tracefile):
    with open(tracefile, 'r') as fd:
        data = fd.read().strip()
    lines = data.split('\n')[1:]    # skip the 1st line
    trace = []
    for l in lines:
        addr = int(l.split(':')[1].split(']')[0], 16)
        # skip exception vector stub
        if addr&0xffff0000 == 0xffff0000:
            continue
        trace.append(addr)
    return trace

tracefiles = [trace_buckets[f].getone() for f in trace_buckets.keys()]
kernelfile = "/data/tonyhu/irq/log/home/moyix/bbb/build/tmp/work/beaglebone-poky-linux-gnueabi/linux-stable/5.7.14-r0/build/vmlinux"
outdir = "/data/tonyhu/irq/log/diffout"

traces = []
for tf in tracefiles:
    traces.append({'dir': tf, 'full_trace': parse_trace(tf)})

DiffSliceAnalyzer().bn_analyze(traces, kernelfile, outdir)
