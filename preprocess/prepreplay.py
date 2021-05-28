#!/usr/bin/python3

import os
import re
import sys

replaylog = sys.argv[1]
outdir = sys.argv[2]

NPROC = 200
ioseqs = [[] for i in range(NPROC)]

with open(replaylog, 'r') as fd:
    lines = fd.read().split('\n')

pat = re.compile(r"\(0x[0-9a-f]+,(0x[0-9a-f]+)\)")
for i,l in enumerate(lines):
    ioseqs[i%NPROC].append([v for v in pat.findall(l)])

if not os.path.exists(outdir):
    os.makedirs(outdir)
for i in range(NPROC):
    with open(os.path.join(outdir, f"replay_{str(i)}"), 'w') as fd:
        fd.write("\n".join([",".join([v for v in s]) for s in ioseqs[i]]))
