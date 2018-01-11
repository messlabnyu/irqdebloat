/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include "taint2/taint2.h"
#include "taint2/taint2_ext.h"
#include "loadstate/loadstate_ext.h"

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

#include <set>
#include <deque>
#include <sstream>

std::set<uint64_t> ioaddrs_seen;
std::deque<uint64_t> iovals;
uint32_t label_number = 1;

void on_taint_mmio_read(uint64_t paddr, target_ulong vaddr, uint64_t llvm_slot, uint64_t size) {
    if (ioaddrs_seen.find(paddr) == ioaddrs_seen.end()) return;
    target_ulong pc = panda_current_pc(first_cpu);
    target_ulong asid = panda_current_asid(first_cpu);
    printf ("instr=%" PRId64" LABEL %d pc=0x" TARGET_FMT_lx " asid=0x" TARGET_FMT_lx" paddr=%" PRIx64" size=%" PRId64 " llvm_slot=%" PRId64 " labeling\n",
        rr_get_guest_instr_count(), label_number, pc, asid, paddr, size, llvm_slot);
    for (uint32_t o=0; o<size; o++) {
        taint2_label_llvm(llvm_slot, o, label_number);
    }
    label_number++;
}

static void ioread(CPUState *env, target_ulong pc, hwaddr addr, uint32_t size, uint64_t *val) {
    static int fd = -1;
    if (fd == -1) fd = open("/dev/urandom", O_RDONLY);
    ioaddrs_seen.insert(addr);
    if (!iovals.empty()) {
        *val = iovals.front();
        iovals.pop_front();
    }
    else {
        assert(read(fd, val, sizeof(*val)) > 0);
    }
}

static void on_tainted_pc(Addr a, uint64_t size) {
    printf("Saw jump to tainted addr!\n");
}

bool interrupt = false;
uint64_t bb_counter = 0;
const char *memfile;
const char *cpufile;

void after_machine_init(CPUState *env) {
    //printf("TB: " TARGET_FMT_lx "\n", tb->pc);
    load_states(env, memfile, cpufile);
    //printf("Enabling taint at pc=" TARGET_FMT_lx "\n", tb->pc);
    taint2_enable_tainted_pointer();
    taint2_enable_taint();
    if (interrupt) cpu_interrupt(env, CPU_INTERRUPT_HARD);
}

bool init_plugin(void *self) {
    panda_require("taint2");
    if (!init_taint2_api()) return false;
    panda_require("loadstate");
    if (!init_loadstate_api()) return false;

    PPP_REG_CB("taint2", on_taint_after_load, on_taint_mmio_read);
    PPP_REG_CB("taint2", on_indirect_jump, on_tainted_pc);

    panda_arg_list *args = panda_get_args("iotaint");
    const char *iovs = panda_parse_string(args, "iovals", "");
    std::istringstream ss(iovs);
    std::string s;
    while (std::getline(ss, s, '|')) {
        iovals.push_back(strtoul(s.c_str(), NULL, 16));
    }
    memfile = panda_parse_string(args, "mem", "mem");
    cpufile = panda_parse_string(args, "cpu", "cpu");
    interrupt = panda_parse_bool(args, "interrupt");

    panda_cb pcb = { .unassigned_io_read = ioread };
    panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);
    pcb.after_machine_init = after_machine_init;
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);

    return true;
}

void uninit_plugin(void *self) { }
