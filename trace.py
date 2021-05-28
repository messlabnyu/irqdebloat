#!/usr/bin/python3

import os
import sys
import time
import argparse
import subprocess

DIR = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
ENV = {"LD_LIBRARY_PATH": os.path.join(DIR, "llvm/lib")}
NPROC = 200

def build_cmd(ostag, out, reg, mem, index=None, replay=None, iolist=None, nullpad=True,compact=False,cntpct=0):
    if index != None:
        outdir = os.path.join(DIR, out, "qemu_"+str(index))
    else:
        outdir = os.path.join(DIR, out)
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    if ostag == "romulus":
        cpu = 'arm1176'
        memrange = '0x80000000-0x90000000'
    elif ostag == "beagle":
        cpu = 'cortex-a8'
        memrange = '0x80000000-0x90000000'
    elif ostag in ["linux", "linux_virt", "freebsd", "riscos"]:
        cpu = 'cortex-a7'
        memrange = '0x00000000-0x3f000000'
    elif ostag in ["sabre", "vxwork"]:
        cpu = 'cortex-a9'
        memrange = '0x10000000-0x18000000'
    elif ostag == "nuri":
        cpu = 'cortex-a9'
        memrange = '0x40000000-0x80000000'

    if replay == None:
        if index != None:
            candi = [i*NPROC+index for i in range(int(32/NPROC)+1) if i*NPROC+index <= 32]
            enum_args = [
                    'enuml1', f'l1={"|".join([hex((1<<i)&0xffffffff)[2:] for i in range(33)])}',
                    'enuml2', f'l2={"|".join([hex((1<<i)&0xffffffff)[2:] for i in candi])}',
                    'enuml3', f'l3={"|".join([hex((1<<i)&0xffffffff)[2:] for i in range(33)])}',
                    #'enuml4', f'l4={"|".join([hex((1<<i)&0xffffffff)[2:] for i in range(33)])}',
                    ]
        else:
            enum_args = [
                    'enuml1', f'l1={"|".join([hex((1<<i)&0xffffffff)[2:] for i in range(33)])}',
                    #'enuml2',
                    #'enuml3',
                    ]
        ioargs = [f'tracedir={outdir}', f'mem={mem}', f'cpu={reg}', f'{",".join(enum_args)}',
                'tracelimit', 'interrupt', 'auto']
    else:
        ioargs = [f'tracedir={outdir}', f'mem={mem}', f'cpu={reg}', f'replay={replay}',
                'tracelimit', 'interrupt']
    # Raspberry Pi Linux: calibrate timer with random IRQ after machine state reset
    if ostag == "linux":
        #ioargs.append('calib')
        ioargs.append(f'cntpct={hex(cntpct)[2:]}')
    if ostag == "riscos":
        ioargs.append('nosvc')
    if ostag == "vxwork":
        ioargs.append('clearirq')
    if nullpad:
        ioargs.append('null')
    if compact:
        ioargs.extend(['pack', 'dedup'])
    if iolist:
        ioargs.append(f'iolist={iolist}')
    #ioargs.append('debug')

    cmd = [os.path.join(DIR, "irq_fuzzer/build/arm-softmmu/qemu-system-arm"),
            '-machine', f'rehosting,mem-map=MEM {memrange}',
            '-panda', f'ioreplay:{",".join(ioargs)}',
            '-cpu', f'{cpu}',
            '-display', 'none',
            ]
    print(cmd)
    return cmd

def mc(ostag, outdir, reg, mem, null=True,replaydir=None,iolist=None,tar=True,cntpct=0):
    if replaydir:
        comp = None
        cleaner = None
        rmcmd = None
        for d,_,fs in os.walk(replaydir):
            replaylog = [os.path.join(d,f) for f in fs]
        for bi in range(0, len(replaylog), NPROC):
            pool = [subprocess.Popen(
                build_cmd(ostag, outdir, reg, mem, index=bi+i,compact=True,iolist=iolist,cntpct=cntpct,
                    replay=os.path.join(replaydir,f"replay_{str(bi+i)}"),nullpad=null),
                env=ENV)
                for i in range(min(NPROC, len(replaylog)-bi))]
            map(lambda x: os.sched_setaffinity(pool[x].pid, {hex(1<<x)}), range(len(pool)))
            while None in map(lambda x: x.poll(), pool):
                time.sleep(60)
                print(map(lambda x: x.poll(), pool))

            # async compress results
            if comp:
                comp.wait()
                # pipeline a remove cmd, cause tar --remove-files is sooooo sloooooow
                if cleaner:
                    cleaner.wait()
                cleaner = subprocess.Popen(rmcmd)
            if tar:
                compcmd = ['tar', '-czf', os.path.join(outdir, f'{str(bi)}_{str(bi+len(pool)-1)}.tar.gz')]  # ,'--remove-files']
                rmcmd = ['rm', '-rf']
                compcmd.extend([os.path.join(outdir, f"qemu_{str(bi+i)}") for i in range(len(pool))])
                rmcmd.extend([os.path.join(outdir, f"qemu_{str(bi+i)}") for i in range(len(pool))])
                comp = subprocess.Popen(compcmd)
        if comp:
            comp.wait()
            if cleaner:
                cleaner.wait()
            subprocess.Popen(rmcmd).wait()
    else:
        pool = [subprocess.Popen(build_cmd(ostag, outdir, reg, mem, index=i,iolist=iolist,nullpad=null,compact=True,cntpct=cntpct),env=ENV) for i in range(NPROC)]
        map(lambda x: os.sched_setaffinity(pool[x].pid, {hex(1<<x)}), range(NPROC))
        while None in map(lambda x: x.poll(), pool):
            time.sleep(60)
            print(map(lambda x: x.poll(), pool))

def debug(ostag, outdir, reg, mem, null=True,iolist=None,replay=None,cntpct=0):
    p = subprocess.Popen(build_cmd(ostag, outdir, reg, mem, iolist=iolist,replay=replay,nullpad=null,cntpct=cntpct), env=ENV)
    os.sched_setaffinity(p.pid, {3})
    try:
        p.wait(timeout=4*60*60) # 4 hours timeout
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()
    print(p.poll())

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('ostag')
    parser.add_argument('outdir')
    parser.add_argument('reg')
    parser.add_argument('mem')
    parser.add_argument('--replay', '-r', default=None)
    parser.add_argument('--iolist', '-l', default=None)

    args = parser.parse_args()

    outdir = os.path.join(DIR, args.outdir)
    reg = os.path.join(DIR, args.reg)
    mem = os.path.join(DIR, args.mem)

    # Ensure that RaspberryPi Linux emulation has CNTPCT (emulated coprocessor) no less than the stored counter value to avoid (infinite) loops while irq_enter
    # The stored counter value is reverse engineered through (timekeeper_advance)arch_counter_get_cntpct, mm._read_word(mm.translate(0x80DC0828))
    #debug(args.ostag, outdir, reg, mem, replay=args.replay, iolist=args.iolist, cntpct=0x31186096)
    mc(args.ostag, outdir, reg, mem, replaydir=args.replay, iolist=args.iolist, cntpct=0x31186096)
