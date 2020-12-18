#!/usr/bin/env python3

import sys
import yaml

CPSR_MODE = 0x1F
MODE_USR = 0x10
MODE_FIQ = 0x11
MODE_IRQ = 0x12
MODE_SVC = 0x13
MODE_MON = 0x16
MODE_ABT = 0x17
MODE_UND = 0x1B
MODE_SYS = 0x1F

# Mode names in the order that QEMU's arrays store them
# Note: armv7 without VE does not use hyp
ordered_modes = ["usr", "svc", "abt", "und", "irq", "fiq", "hyp", "mon"]

# CPSR DAIF flags. Note that D flag doesn't exist outside of aarch64
PSTATE_F =(1 << 6)
PSTATE_I =(1 << 7)
PSTATE_A =(1 << 8)
PSTATE_DAIF = (PSTATE_A | PSTATE_I | PSTATE_F)

modenames = {
    MODE_USR: "usr",
    MODE_FIQ: "fiq",
    MODE_IRQ: "irq",
    MODE_SVC: "svc",
    MODE_MON: "mon",
    MODE_ABT: "abt",
    MODE_UND: "und",
    MODE_SYS: "sys",
}

regs = {}

for line in open(sys.argv[1]):
    assert '=' in line or ':' in line
    k, _, v = line.strip().split()
    regs[k] = int(v,0)

mode = regs['cpsr'] & CPSR_MODE
mode_string = modenames[mode]

# General purpose registers
print("regs:")
for i in range(13):
    print(' '*4 + '- ' + '{:#010x}'.format(regs[f'r{i}']))
print(' '*4 + '- ' + '{:#010x}'.format(regs[f'sp_{mode_string}']))
print(' '*4 + '- ' + '{:#010x}'.format(regs[f'lr_{mode_string}']))
print(' '*4 + '- ' + '{:#010x}'.format(regs['pc']))

daif = regs['cpsr'] & PSTATE_DAIF
print(f"daif: {daif:#x}")
print(f"cp15.dacr_ns: 0x0")
print(f"cp15.dacr_s: {regs['domain_access_control_0']:#x}") 
print(f"cp15.ttbr0_el:")
for _ in range(3):
    print("    - 0x00000000")
print(f"    - {regs['translation_table_base_0_0']:#010x}")
print(f"cp15.ttbr1_el:")
for _ in range(3):
    print("    - 0x00000000")
print(f"    - {regs['translation_table_base_1_0']:#010x}")
print(f"cp15.sctlr_el:")
for _ in range(3):
    print("    - 0x00000000")
print(f"    - {regs['control_0']:#010x}")
print(f"cp15.vbar_el:")
for _ in range(3):
    print("    - 0x00000000")
print(f"    - {regs['secure_or_nonsecure_vector_base_address_0']:#010x}")
print(f"cp15.scr_el3: 0x0")
print(f"cp15.hcr_el2: 0x0")
print(f"uncached_cpsr: {mode:#x}")
print("spsr: {:#010x}".format(regs[f'spsr_{mode_string}']))
print("banked_spsr:")
for name in ordered_modes:
    if name == "usr": name = "spsr"
    else: name = f"spsr_{name}"
    val = regs.get(name, 0)
    print(' '*4 + '- ' + f"{val:#010x}")
print("banked_r13:")
for name in ordered_modes:
    name = f"sp_{name}"
    val = regs.get(name, 0)
    print(' '*4 + '- ' + f"{val:#010x}")
print("banked_r14:")
for name in ordered_modes:
    name = f"lr_{name}"
    val = regs.get(name, 0)
    print(' '*4 + '- ' + f"{val:#010x}")

print(f"tpidrprw: {regs['privileged_only_thread_and_process_id_0']:#010x}")
