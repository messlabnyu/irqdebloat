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
#define MAX_BLOCKS 1000000

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
#include <vector>
#include <fstream>


std::set<uint64_t> ioaddrs_seen;
std::deque<uint64_t> iovals;
std::deque<uint64_t> l1_nums, l2_nums, l3_nums;
uint32_t label_number = 1;
#define HWIRQ_FUZZ_TRY  3
static int start_new_irq = HWIRQ_FUZZ_TRY;

bool interrupt = false;
bool fiq = false;
bool ioreplay_debug = false;
bool limit_trace = false;
uint64_t bb_counter = 0;
const char *memfile;
const char *cpufile;
const char *tracedir;
uint64_t num_blocks = 0;
uint32_t start;

#ifndef TARGET_ARM
#define CPU_INTERRUPT_FIQ 0
#endif

extern "C" {
#include <qemu/timer.h>
}
static uint64_t start_time = 0;
// 1 minutes
#define MAX_TRACE_TIMER_MS  (1*60*1000)

#ifdef TARGET_ARM
static uint32_t prev_cpu_mode = 0;
static uint64_t trace_count = 0;
static std::vector<gchar*> ioseq;
#endif

static void ioread(CPUState *env, target_ulong pc, hwaddr addr, uint32_t size, uint64_t *val) {
    static int fd = -1;
    CPUArchState *cpu = (CPUArchState *)env->env_ptr;
    if (fd == -1) fd = open("/dev/urandom", O_RDONLY);
    //ioaddrs_seen.insert(addr);
    if (!iovals.empty()) {
        *val = iovals.front();
        iovals.pop_front();
    }
    else {
        assert(read(fd, val, sizeof(*val)) > 0);
    }
    if (start_new_irq) {
        //*val = (1 << ((*val)&0x3f)) | (1 << (((*val)>>8)&0x1f));
        switch(start_new_irq) {
        case HWIRQ_FUZZ_TRY:
            if (!l1_nums.empty())
                *val = l1_nums[(*val)%l1_nums.size()];
            break;
        case HWIRQ_FUZZ_TRY-1:
            if (!l2_nums.empty())
                *val = l2_nums[(*val)%l2_nums.size()];
            break;
        case HWIRQ_FUZZ_TRY-2:
            if (!l3_nums.empty())
                *val = l3_nums[(*val)%l3_nums.size()];
            break;
        }

        start_new_irq--;
        //*val = (1 << 8);
        //start_new_irq = 0;
    }
#ifdef TARGET_ARM
    ioseq.emplace_back(
            g_strdup_printf("IO READ pc=" TARGET_FMT_lx " addr=%08" HWADDR_PRIx " size %u val=%08" PRIx64 "\n",
                cpu->regs[15], addr, size, *val));
    if (ioreplay_debug) 
        printf("IO READ pc=" TARGET_FMT_lx " addr=%08" HWADDR_PRIx " size %u val=%08" PRIx64 "\n",
            cpu->regs[15], addr, size, *val);
#endif
}

static void top_loop(CPUState *cpu) {
    load_states(cpu, memfile, cpufile);
}

extern bool panda_exit_loop;
static bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb) {
    num_blocks++;
    if (limit_trace && qemu_loglevel && num_blocks > MAX_BLOCKS) {
        panda_exit_loop = true;
        printf("Truncate Trace (max block number exceeded)\n");
        qemu_loglevel = 0;
        num_blocks = 0;
        return true;
    }
    return false;
}

static int before_block_exec(CPUState *env, TranslationBlock *tb) {
#ifdef TARGET_ARM
    // Cortex-A exception vector:
    // https://developer.arm.com/documentation/ddi0301/h/programmer-s-model/exceptions/exception-vectors
    CPUArchState *cpu = (CPUArchState *)env->env_ptr;
    uint32_t cpu_mode = cpu->uncached_cpsr & CPSR_M;
    switch (cpu_mode) {
    case ARM_CPU_MODE_FIQ:
    case ARM_CPU_MODE_IRQ:
    case ARM_CPU_MODE_SVC:
    case ARM_CPU_MODE_ABT:
        // ignore the very initial exectution
        if (!prev_cpu_mode) break;
        // cpu_mode changed to FIQ/IRQ/SVC indicates entering interrupt handling
        if (cpu_mode^prev_cpu_mode) {
            fprintf(stderr, "DEBUG [%x] cpsr %x, prev %x\n", cpu->regs[15], cpsr_read(cpu), prev_cpu_mode);
            qemu_log_flush();

            if (qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - start_time > MAX_TRACE_TIMER_MS) {
                printf("Done with ioreplay (max time %d ms)\n", MAX_TRACE_TIMER_MS);
                exit(0);
            }

            //qemu_loglevel |= CPU_LOG_TB_IN_ASM|CPU_LOG_INT|CPU_LOG_TB_CPU;
            qemu_loglevel |= CPU_LOG_EXEC|CPU_LOG_TB_NOCHAIN;
            char *newlog = g_strdup_printf("%s/trace_%lld.log", tracedir, trace_count);
            qemu_set_log_filename(newlog, nullptr);
            qemu_log("cpu mode: %x, prev: %x\n", cpu_mode, prev_cpu_mode);
            qemu_log("Trace [0: %08x] cpsr %x, prev %x\n", cpu->regs[15], cpsr_read(cpu), prev_cpu_mode);

            // log io vals
            if (!ioseq.empty() && trace_count) {    // ignores any io before actually started logging traces
                char *iolog = g_strdup_printf("%s/iovals_%ld.log", tracedir, trace_count-1);
                std::ofstream os(iolog, std::ofstream::out);
                for (gchar *v : ioseq) {
                    os << v;
                    g_free(v);
                }
                os.close();
                g_free(iolog);
            }
            ioseq.clear();

            trace_count++;
            num_blocks = 0;

            if (cpu_mode != ARM_CPU_MODE_ABT)
                start_new_irq = HWIRQ_FUZZ_TRY;
        }
        break;
    default:
        break;
    }
    prev_cpu_mode = cpu_mode;
#endif
    return 0;
}
void after_machine_init(CPUState *env) {
    //printf("TB: " TARGET_FMT_lx "\n", tb->pc);
    load_states(env, memfile, cpufile);
    //printf("Enabling taint at pc=" TARGET_FMT_lx "\n", tb->pc);
    start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
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
    limit_trace = panda_parse_bool(args, "tracelimit");
    tracedir = panda_parse_string(args, "tracedir", "../log/trace");
    const char *l1 = panda_parse_string(args, "l1", "");
    ss.str(l1);
    while (std::getline(ss, s, '|')) {
        l1_nums.push_back(strtoul(s.c_str(), NULL, 16));
    }
    const char *l2 = panda_parse_string(args, "l2", "");
    ss.str(l2);
    while (std::getline(ss, s, '|')) {
        l2_nums.push_back(strtoul(s.c_str(), NULL, 16));
    }
    const char *l3 = panda_parse_string(args, "l3", "");
    ss.str(l3);
    while (std::getline(ss, s, '|')) {
        l3_nums.push_back(strtoul(s.c_str(), NULL, 16));
    }

    panda_cb pcb = { .unassigned_io_read = ioread };
    panda_register_callback(self, PANDA_CB_UNASSIGNED_IO_READ, pcb);
    pcb.after_machine_init = after_machine_init;
    panda_register_callback(self, PANDA_CB_AFTER_MACHINE_INIT, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
    pcb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, pcb);
    pcb.top_loop = top_loop;
    panda_register_callback(self, PANDA_CB_TOP_LOOP, pcb);

    start = time(NULL);

    return true;
}

void uninit_plugin(void *self) { }
