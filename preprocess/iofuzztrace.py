import os
import sys
import struct
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('indir')
parser.add_argument('outdir')
parser.add_argument('--cacheio', '-c', action='store_true')
parser.add_argument('--blacklist', '-l', default=None)

args = parser.parse_args()

indir = args.indir
outdir = args.outdir
blacklist = []
if args.blacklist:
    with open(args.blacklist, 'r') as fd:
        blacklist = [int(l,16) for l in fd.read().strip().split('\n')]

trindex = 0
traces = {0:[]}
ioindex = 0
iovals = {0:[]}
read_regs = {}
write_regs = {}
replayseq = []

for r,_,fs in os.walk(indir):
    for f in fs:
        if not f.endswith(".btrace"):
            continue
        with open(os.path.join(r,f), 'rb') as fd:
            data = fd.read()
        seenfirstentry = False
        ioseq = []
        for i in range(0,len(data),16):
            if struct.unpack('<I', data[i:i+4])[0] == 0:
                addr = struct.unpack('<I', data[i+4:i+8])[0]
                if addr in [0xffff0018, 0x257804, 0xfc012900]:
                    seenfirstentry = True
                    trindex += 1
                if not seenfirstentry:
                    continue
                if trindex < len(traces):
                    traces[trindex].append(addr)
                elif trindex == len(traces):
                    traces[trindex] = [addr]
            elif struct.unpack('<I', data[i:i+4])[0] == 1:
                pc = struct.unpack('<I', data[i+4:i+8])[0]
                addr = struct.unpack('<I', data[i+8:i+12])[0]
                val = struct.unpack('<I', data[i+12:i+16])[0]
                iovals[ioindex].append((pc, addr, val, 1))
                if addr not in read_regs:
                    read_regs[addr] = 0
                read_regs[addr] += 1
                # ignore blacklisted MMIO registers
                if addr in blacklist:
                    continue
                if addr not in [a[0] for a in ioseq]:
                    ioseq.append((addr,val,pc))
                elif args.cacheio and addr in [a[0] for a in ioseq] and val in [a[1] for a in ioseq if a[0]==addr]:
                    ioseq.append((addr,val,pc))
                else:
                    replayseq.append([(s[0],s[1],s[2]) for s in ioseq])
                    while addr in [a[0] for a in ioseq]:
                        ioseq = ioseq[:-1]
                    ioseq.append((addr, val,pc))

            elif struct.unpack('<I', data[i:i+4])[0] == 2:
                pc = struct.unpack('<I', data[i+4:i+8])[0]
                addr = struct.unpack('<I', data[i+8:i+12])[0]
                val = struct.unpack('<I', data[i+12:i+16])[0]
                iovals[ioindex].append((pc, addr, val, 2))
                if addr not in write_regs:
                    write_regs[addr] = 0
                write_regs[addr] += 1
        ioindex += 1
        iovals[ioindex] = []
        replayseq.append([s for s in ioseq])

# output traces
for i in traces:
    if i == 0:
        continue
    with open(os.path.join(outdir, 'trace_{}'.format(str(i))), 'w') as fd:
        fd.write("cpu mode: 13, prev: 12\n")
        fd.write("\n".join(["Trace :"+hex(a) for a in traces[i]]))
# output iovals
#for i in iovals:
#    with open(os.path.join(outdir, 'iovals_{}'.format(str(i))), 'w') as fd:
#        fd.write("\n".join([",".join([hex(a[0]), hex(a[1]), hex(a[2]), 'read' if a[3] == 1 else 'write']) for a in iovals[i]]))

# output de-looped ioseq - !!Blacklist the io addresses that has siginificantly high counts
def print_seq(l):
    l.sort(key=lambda x: x[1])
    for addr, cnt in l:
        print(hex(addr), cnt)
print("read only MMIO regs:")
print_seq([(addr, cnt) for addr,cnt in read_regs.items() if addr not in write_regs])
print("all read MMIO regs:")
print_seq([(addr, cnt) for addr,cnt in read_regs.items()])
print("write only MMIO regs:")
print_seq([(addr, cnt) for addr,cnt in write_regs.items() if addr not in read_regs])
print("all write MMIO regs:")
print_seq([(addr, cnt) for addr,cnt in write_regs.items()])
print("all read/write MMIO regs:")
for r,c in read_regs.items():
    if r in write_regs:
        write_regs[r] += c
    else:
        write_regs[r] = c
print_seq([(addr, cnt) for addr,cnt in write_regs.items()])
print("#ioseq: ", len(replayseq))
#seqlist = [tuple([hex(t[0]) for t in s]) for s in replayseq]
#seqstat = {}
#for t in seqlist:
#    if t not in seqstat:
#        seqstat[t] = seqlist.count(t)
#for s,c in seqstat.items():
#    print(s, ":", c)
with open(os.path.join(outdir, 'replay'), 'w') as fd:
    fd.write("\n".join([",".join(["("+hex(t[0])+","+hex(t[1])+")" for t in s]) for s in replayseq]))
with open(os.path.join(outdir, 'debugio'), 'w') as fd:
    fd.write("\n".join([",".join(["("+hex(t[0])+","+hex(t[1])+","+hex(t[2])+")" for t in s]) for s in replayseq]))
