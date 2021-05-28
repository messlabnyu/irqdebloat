#!/usr/bin/env python3

import csv
import sys
import itertools

f = open(sys.argv[1])
rd = csv.DictReader(f)

arm_regs = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
    "r12", "sp_usr", "lr_usr", "pc", "r8_fiq", "r9_fiq", "r10_fiq", "r11_fiq",
    "r12_fiq", "sp_fiq", "lr_fiq", "sp_irq", "lr_irq", "sp_svc", "lr_svc",
    "sp_abt", "lr_abt", "sp_und", "lr_und", "cpsr", "spsr_fiq", "spsr_irq",
    "spsr_svc", "spsr_abt", "spsr_und", "sp", "lr", "sp_mon", "lr_mon",
    "spsr_mon", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9",
    "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19",
    "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30"
]

def parse_range(s):
    items = []
    if s.startswith("{"):
        parts = [p.strip() for p in s[1:-1].split(',')]
    else:
        parts = [s]
    for p in parts:
        if '-' in p:
            st,ed = p.split('-')
            items.extend(range(int(st),int(ed)+1))
        else:
            items.append(int(p))
    return items

def snake_case(s):
    return s.replace(' ','_').lower()

print("log_output beaglebone.reg")
for row in rd:
    if row['Register or operation'] == 'Undefined':
        #print("Skipping undefined coprocessor register")
        continue
    if row['Security state (NS)'] == 'NA':
        #print("Skipping register only available in Secure mode: "
        #        + row['Register or operation'])
        continue
    if 'WO' in row['Security state (NS)']:
        #print("Skipping write-only register: " + row['Register or operation'])
        continue
    crn = parse_range(row['CRn'].replace('c',''))
    op1 = parse_range(row['Op1'])
    crm = parse_range(row['CRm'].replace('c',''))
    op2 = parse_range(row['Op2'])
    print(f"# {row['Register or operation']}")
    varname = snake_case(row['Register or operation'])
    for (i, (o1, n, m, o2)) in enumerate(itertools.product(op1, crn, crm, op2)):
        #print(f"mrc p15, {o1}, <Rt>, c{n}, c{m}, {o2}")
        print(f'echo [format "{varname}_{i} = %#x" [arm mrc 15 {o1} {n} {m} {o2}]]')

for reg in arm_regs:
    print(f'echo -n [reg {reg}]')
print("log_output")
