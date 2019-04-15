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
#define MAX_BLOCKS 100000

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
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

bool interrupt = false;
bool fiq = false;
bool ioreplay_debug = false;
uint64_t bb_counter = 0;
const char *memfile;
const char *cpufile;
uint64_t num_blocks = 0;
uint32_t start;

#ifndef TARGET_ARM
#define CPU_INTERRUPT_FIQ 0
#endif

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
    if (ioreplay_debug) 
        printf("IO READ pc=" TARGET_FMT_lx " addr=%08" HWADDR_PRIx " size %u val=%08" PRIx64 "\n",
            pc, addr, size, *val);
}

static int before_block_exec(CPUState *env, TranslationBlock *tb) {
    num_blocks++;
    if (num_blocks > MAX_BLOCKS) {
        printf("Done with ioreplay (max block number exceeded)\n");
        exit(0);
    }
    return 0;
}
void after_machine_init(CPUState *env) {
    //printf("TB: " TARGET_FMT_lx "\n", tb->pc);
    load_states(env, memfile, cpufile);
    //printf("Enabling taint at pc=" TARGET_FMT_lx "\n", tb->pc);
    if (interrupt)
        cpu_interrupt(env, CPU_INTERRUPT_HARD |
            (fiq ? CPU_INTERRUPT_FIQ : 0));
}

bool init_plugin(void *self) {
    panda_require("loadstate");
    if (!init_loadstate_api()) return false;

    panda_arg_list *args = panda_get_args("ioreplay");
    const char *iovs = panda_parse_string(args, "iovals", "");
    std::istringstream ss(iovs);
    std::string s;
    while (std::getline(ss, s, '|')) {
        iovals.push_back(strtoul(s.c_str(), NULL, 16));
    }
    memfile = panda_parse_string(args, "mem", "mem");
    cpufile = panda_parse_string(args, "cpu", "cpu");
    interrupt = panda_parse_bool(args, "interrupt");
    fiq = panda_parse_bool(args, "fiq");
    ioreplay_debug = panda_parse_bool(args, "debug");

    panda_cb pcb = { .unassigned_io_read = ioread };
    panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);
    pcb.after_machine_init = after_machine_init;
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    start = time(NULL);

    return true;
}

void uninit_plugin(void *self) { }
