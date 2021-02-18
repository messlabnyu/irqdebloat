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
#include <vector>
#include <fstream>

std::set<uint64_t> ioaddrs_seen;
std::deque<uint64_t> iovals;
std::deque<uint64_t> l1_nums, l2_nums, l3_nums, l4_nums;
bool enum_l1 = false, enum_l2 = false, enum_l3 = false, enum_l4=false;
uint64_t l1index = 0, l2index = 0, l3index = 0, l4index = 0;
uint64_t l1cycle = 0, l2cycle = 0, l3cycle = 0, l4cycle = 0;
bool l1cycle_updated = false, l2cycle_updated = false, l3cycle_updated = false, l4cycle_updated = false;
// No auto blacklist for first and last layer
bool l2_blacklist = false, l3_blacklist= false;
uint32_t label_number = 1;
#define HWIRQ_FUZZ_TRY  4
static int start_new_irq = HWIRQ_FUZZ_TRY;
#define TIMER_IRQ_ROUNDS    1
static int irq_rounds = 0;
static uint64_t replay_line = 0, replay_index = 0;
static std::vector<std::vector<uint64_t>> replay_ioseqs;
static char *trace_seq_log = nullptr;
static std::vector<target_ulong> trace_seq;
static bool log_compact = 0;
static std::set<target_ulong> timer_io;

bool clear_irq = false;
bool quickdedup = false;
bool compact_output = false;
bool init_calibrate = false;
bool auto_enum = false;
bool nosvc = false;
bool feed_null = false;
bool interrupt = false;
bool fiq = false;
bool ioreplay_debug = false;
bool limit_trace = false;
uint64_t bb_counter = 0;
std::vector<const char *> memfile;
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

static uint32_t prev_cpu_mode = 0;
static uint64_t trace_start = 0;
static uint64_t trace_count = 0;
static std::vector<gchar*> ioseq;

#ifdef TARGET_ARM
#define LOG_IO_TRACE \
        if (!compact_output) \
            ioseq.emplace_back( \
                    g_strdup_printf("IO READ pc=" TARGET_FMT_lx " addr=%08" HWADDR_PRIx " size %u val=%08" PRIx64 "\n", \
                        cpu->regs[15], addr, size, *val)); \
        if (ioreplay_debug) \
            printf("IO READ pc=" TARGET_FMT_lx " addr=%08" HWADDR_PRIx " size %u val=%08" PRIx64 "\n", \
                cpu->regs[15], addr, size, *val);
#else
#define LOG_IO_TRACE
#endif
static void ioread(CPUState *env, target_ulong pc, hwaddr addr, uint32_t size, uint64_t *val) {
    static int fd = -1;
    CPUArchState *cpu = (CPUArchState *)env->env_ptr;
    if (fd == -1) fd = open("/dev/urandom", O_RDONLY);
    if (init_calibrate && irq_rounds <= TIMER_IRQ_ROUNDS) {
        //*val = 2;
        assert(read(fd, val, sizeof(*val)) > 0);
        LOG_IO_TRACE
        return;
    }
    // Feed random value until IRQ fire for the first time
    if (trace_count == trace_start) {
        if (feed_null)
            *val = 0;
        else
            assert(read(fd, val, sizeof(*val)) > 0);
        return;
    }
    // Feed arbitrary number to Timer IO to avoid dead loop
    if (!timer_io.empty()) {
        if (timer_io.find(addr) != timer_io.end()) {
            assert(read(fd, val, sizeof(*val)) > 0);
	    if ((*val)&1)
                *val = 0xffffffff;
	    else
                *val = 0;
            return;
        }
    }
    // Replay from ioseq log
    if (!replay_ioseqs.empty()) {
        if (replay_index < replay_ioseqs[replay_line].size())
            *val = replay_ioseqs[replay_line][replay_index++];
        else if (feed_null)
            *val = 0;
        else
            assert(read(fd, val, sizeof(*val)) > 0);
        LOG_IO_TRACE
        return;
    }
    //ioaddrs_seen.insert(addr);
    if (!iovals.empty()) {
        *val = iovals.front();
        iovals.pop_front();
    }
    else {
        if (feed_null)
            *val = 0;
        else
            assert(read(fd, val, sizeof(*val)) > 0);
    }
    if (start_new_irq) {
        //*val = (1 << ((*val)&0x3f)) | (1 << (((*val)>>8)&0x1f));
        switch(start_new_irq) {
        case HWIRQ_FUZZ_TRY:
            if (enum_l1) {
                *val = l1_nums[l1index++];
                l1cycle_updated = false;
                if (l1index == l1_nums.size()) {
                    l1cycle++;
                    l1cycle_updated = true;
                    l1index = 0;
                }
            } else {
                if (!l1_nums.empty())
                    *val = l1_nums[(*val)%l1_nums.size()];
            }
            break;
        case HWIRQ_FUZZ_TRY-1:
            if (enum_l2) {
                *val = l2_nums[l2index];
                if (l1cycle_updated)
                    l2index++;
                l2cycle_updated = false;
                if (l2index == l2_nums.size()) {
                    l2cycle++;
                    l2cycle_updated = true;
                    l2index = 0;
                    l1index = 0;
                }
            } else {
                if (!l2_nums.empty())
                    *val = l2_nums[(*val)%l2_nums.size()];
            }
            break;
        case HWIRQ_FUZZ_TRY-2:
            if (enum_l3) {
                *val = l3_nums[l3index];
                if (l2cycle_updated)
                    l3index++;
                l3cycle_updated = false;
                if (l3index == l3_nums.size()) {
                    l3cycle++;
                    l3cycle_updated = true;
                    l3index = 0;
                    l2index = 0;
                    l1index = 0;
                }
            } else {
                if (!l3_nums.empty())
                    *val = l3_nums[(*val)%l3_nums.size()];
            }
            break;
        case HWIRQ_FUZZ_TRY-3:
            if (enum_l4) {
                *val = l4_nums[l4index];
                if (l3cycle_updated)
                    l4index++;
                l4cycle_updated = false;
                if (l4index == l4_nums.size()) {
                    l4cycle++;
                    l4cycle_updated = true;
                    l4index = 0;
                    l3index = 0;
                    l2index = 0;
                    l1index = 0;
                }
            } else {
                if (!l4_nums.empty())
                    *val = l4_nums[(*val)%l4_nums.size()];
            }
            break;
        }

        start_new_irq--;
        //*val = (1 << 8);
        //start_new_irq = 0;
    }
    LOG_IO_TRACE
}

void check_replay_status() {
    if (init_calibrate && irq_rounds <= TIMER_IRQ_ROUNDS)
        return;
    if (!replay_ioseqs.empty()) {
        replay_line++;
        replay_index = 0;
        if (replay_line == replay_ioseqs.size())
            exit(0);
    }
}

void track_dead_ioread() {
    if (!auto_enum) return;

    switch (start_new_irq) {
    case 3:
        if (enum_l2 && l1cycle_updated) {
            l2index++;
            if (l2index == l2_nums.size()) {
                l2index = 0;
                l2cycle++;
                l2cycle_updated = true;
            }
        }
        //break;
    case 2:
        //if (l2_blacklist) {
        //    l2_nums.erase(l2_nums.begin()+l2index);
        //    if (l2index == l2_nums.size()) {
        //        l2index = 0;
        //        l2cycle++;
        //        l2cycle_updated = true;
        //    }
        //}
        if (enum_l3 && l2cycle_updated) {
            l3index++;
            if (l3index == l3_nums.size()) {
                l3index = 0;
                l3cycle++;
                l3cycle_updated = true;
            }
        }
        //break;
    case 1:
        //if (l3_blacklist) {
        //    l3_nums.erase(l3_nums.begin()+l3index);
        //    if (l3index == l3_nums.size()) {
        //        l3index = 0;
        //        l3cycle++;
        //        l3cycle_updated = true;
        //    }
        //}
        if (enum_l4 && l3cycle_updated) {
            l4index++;
            if (l4index == l4_nums.size()) {
                l4index = 0;
                l4cycle++;
                l4cycle_updated = true;
            }
        }
        //break;
    default:
        break;
    }
}

static void top_loop(CPUState *cpu) {
    load_states_multi(cpu, memfile.data(), memfile.size(), cpufile);
    // Flush && Reset log state - sometimes we reached here because of tb_exit > TB_EXIT_IDX1
    qemu_loglevel = 0;
    log_compact = 0;
    num_blocks = 0;
    irq_rounds = 0;
}

extern bool panda_exit_loop;
static bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb) {
    num_blocks++;
    //CPUArchState *c = (CPUArchState *)cpu->env_ptr;
    //fprintf(stderr, "DEBUG bb exec %x[%lld:%x]\n", c->regs[15], num_blocks, c->uncached_cpsr&CPSR_M);
    if (limit_trace && (qemu_loglevel || !trace_seq.empty()) && num_blocks > MAX_BLOCKS) {
        panda_exit_loop = true;
        printf("Truncate Trace (max block number exceeded)\n");
        qemu_loglevel = 0;
        log_compact = 0;
        num_blocks = 0;
        irq_rounds = 0;
        return true;
    }
    return false;
}

#ifdef TARGET_ARM
static target_ulong vbar_addr(CPUState *cs) {
    CPUArchState *env = (CPUArchState *)cs->env_ptr;
    target_ulong addr = 0;
    if (A32_BANKED_CURRENT_REG_GET(env, sctlr) & SCTLR_V) {
        /* High vectors. When enabled, base address cannot be remapped. */
        addr += 0xffff0000;
    } else {
        /* ARM v7 architectures provide a vector base address register to remap
         * the interrupt vector table.
         * This register is only followed in non-monitor mode, and is banked.
         * Note: only bits 31:5 are valid.
         */
        addr += A32_BANKED_CURRENT_REG_GET(env, vbar);
    }
    return addr;
}
#endif

static int before_block_exec(CPUState *env, TranslationBlock *tb) {
#ifdef TARGET_ARM
    // Cortex-A exception vector:
    // https://developer.arm.com/documentation/ddi0301/h/programmer-s-model/exceptions/exception-vectors
    CPUArchState *cpu = (CPUArchState *)env->env_ptr;
    uint32_t cpu_mode = cpu->uncached_cpsr & CPSR_M;

    if (compact_output && log_compact && num_blocks < MAX_BLOCKS) {
        if (!quickdedup || trace_seq.empty() || cpu->regs[15]!=trace_seq.back())
            trace_seq.emplace_back(cpu->regs[15]);
    }

    switch (cpu_mode) {
    case ARM_CPU_MODE_FIQ:
    case ARM_CPU_MODE_IRQ:
    case ARM_CPU_MODE_SVC:
    case ARM_CPU_MODE_ABT:
        // ignore the very initial exectution
        if (!prev_cpu_mode) break;
        // cpu_mode changed to FIQ/IRQ/SVC indicates entering interrupt handling
        if (cpu_mode^prev_cpu_mode || cpu->regs[15] == vbar_addr(env)+0x18/*IRQ_ENTRY*/) {
            //fprintf(stderr, "DEBUG [%x](%d) cpsr %x, prev %x\n", cpu->regs[15], env->cpu_index, cpsr_read(cpu), prev_cpu_mode);
            if (!compact_output) {
                qemu_log_flush();

                // log io vals
                if (!ioseq.empty() && trace_count != trace_start) { // ignores any io before actually started logging traces
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
            } else {
                if (trace_seq_log) {
                    if (!quickdedup \
                            || (nosvc && trace_seq[0]==ARM_CPU_MODE_IRQ) \
                            || (!nosvc && trace_seq[1]==ARM_CPU_MODE_IRQ && trace_seq[0]==ARM_CPU_MODE_SVC)) {
                        FILE *f = fopen(trace_seq_log, "wb");
                        fwrite(trace_seq.data(), sizeof(target_ulong), trace_seq.size(), f);
                        fclose(f);
                    }
                    g_free(trace_seq_log);
                    trace_seq_log = nullptr;
                }
            }


            // check exit
            if (replay_ioseqs.empty()) {
                if (!enum_l1 && !enum_l2 && !enum_l3 && !enum_l4) {
                    if (qemu_clock_get_ms(QEMU_CLOCK_REALTIME) - start_time > MAX_TRACE_TIMER_MS) {
                        printf("Done with ioreplay (max time %d ms)\n", MAX_TRACE_TIMER_MS);
                        exit(0);
                    }
                } else if (enum_l4) {   // l4 cycle detection in the highest priority
                    if (l4cycle) {
                        printf("Done l4 irq replay\n");
                        exit(0);
                    } else if (l2_nums.size() == 0 or l3_nums.size() == 0) {
                        printf("l4: l2/3 empty\n");
                        exit(0);
                    }
                } else if (enum_l3) {
                    if (l3cycle) {
                        printf("Done l3 irq replay\n");
                        exit(0);
                    } else if (l2_nums.size() == 0) {
                        printf("l3: l2 empty\n");
                        exit(0);
                    }
                } else if (enum_l2) {
                    if (l2cycle) {
                        printf("Done l2 irq replay\n");
                        exit(0);
                    }
                } else if (enum_l1) {
                    if (l1cycle) {
                        printf("Done l1 irq replay\n");
                        exit(0);
                    }
                }
            }

            if (!compact_output) {
                //qemu_loglevel |= CPU_LOG_TB_IN_ASM|CPU_LOG_INT|CPU_LOG_TB_CPU;
                qemu_loglevel |= CPU_LOG_EXEC|CPU_LOG_TB_NOCHAIN;
                char *newlog = g_strdup_printf("%s/trace_%lld.log", tracedir, trace_count);
                qemu_set_log_filename(newlog, nullptr);
                qemu_log("cpu mode: %x, prev: %x\n", cpu_mode, prev_cpu_mode);
                qemu_log("Trace [0: %08x] cpsr %x, prev %x\n", cpu->regs[15], cpsr_read(cpu), prev_cpu_mode);
            } else {
                log_compact = 1;
                trace_seq_log = g_strdup_printf("%s/trace_%lld.pact", tracedir, trace_count);
                trace_seq.clear();
                trace_seq.emplace_back(cpu_mode);
                trace_seq.emplace_back(prev_cpu_mode);
                trace_seq.emplace_back(cpu->regs[15]);
            }

            trace_count++;
            num_blocks = 0;

            if (nosvc) {
                if (cpu_mode == ARM_CPU_MODE_IRQ) {
                    track_dead_ioread();
                    check_replay_status();
                    start_new_irq = HWIRQ_FUZZ_TRY;
                    irq_rounds++;
                    if (clear_irq)
                        env->interrupt_request = 0;
                } else {
                    if (clear_irq)
                        env->interrupt_request = 1;
                }
            } else {
                if (cpu_mode == ARM_CPU_MODE_SVC && prev_cpu_mode == ARM_CPU_MODE_IRQ) {
                    track_dead_ioread();
                    check_replay_status();
                    start_new_irq = HWIRQ_FUZZ_TRY;
                    irq_rounds++;
                    if (clear_irq)
                        env->interrupt_request = 0;
                } else {
                    if (clear_irq)
                        env->interrupt_request = 1;
                }
            }
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
    load_states_multi(env, memfile.data(), memfile.size(), cpufile);
    //printf("Enabling taint at pc=" TARGET_FMT_lx "\n", tb->pc);
    start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    if (interrupt)
        cpu_interrupt(env, CPU_INTERRUPT_HARD |
            (fiq ? CPU_INTERRUPT_FIQ : 0));
}

static void prepare_enum_2bit(std::deque<uint64_t> &preirq) {
    for (int i = 0; i < 32; i++)
        for (int j = i; j < 32; j++)
            preirq.push_back((1 << i)|(1 << j));
}

static void prepare_enum_1bit(std::deque<uint64_t> &preirq) {
    for (int i = 0; i < 32; i++)
        preirq.push_back(1 << i);
}

static void prepare_hwirq_l1(std::deque<uint64_t> &preirq, panda_arg_list *args, const char *id, bool do_enum) {
    std::istringstream ss(panda_parse_string(args, id, ""));
    std::string s;
    while (std::getline(ss, s, '|')) {
        preirq.push_back(strtoul(s.c_str(), NULL, 16));
    }
    if (do_enum && preirq.empty()) {
        prepare_enum_2bit(preirq);
    }
}

static void prepare_hwirq(std::deque<uint64_t> &preirq, panda_arg_list *args, const char *id, bool do_enum) {
    std::istringstream ss(panda_parse_string(args, id, ""));
    std::string s;
    while (std::getline(ss, s, '|')) {
        preirq.push_back(strtoul(s.c_str(), NULL, 16));
    }
    if (do_enum && preirq.empty()) {
        prepare_enum_1bit(preirq);
    }
}

// Assumed timer MMIO address list, one hex number per line
static void load_timer_io(const char *log) {
    std::string line;
    std::ifstream fs(log);
    while (std::getline(fs, line)) {
        timer_io.emplace(strtoul(line.c_str(), NULL, 16));
    }
}

// Replay log are formatted with one sequence of iovals per line, each ioval is in hex, comma seperated
static void load_replay_log(const char *log) {
    std::string line, s;
    std::ifstream fs(log);
    std::istringstream ss;

    // bootstrap replay ioseqs, we will skip the first one
    replay_ioseqs.emplace_back(std::vector<uint64_t>());
    while (std::getline(fs, line)) {
        ss.str(line);
        ss.clear();
        replay_ioseqs.emplace_back(std::vector<uint64_t>());
        while (std::getline(ss, s, ','))
            replay_ioseqs.back().emplace_back(strtoul(s.c_str(), NULL, 16));
    }
    fs.close();
}

static void parse_memfile_str(const char* memstr) {
    std::istringstream ss(memstr);
    std::string s;
    while (std::getline(ss,s,';'))
        memfile.emplace_back(strdup(s.c_str()));
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
    parse_memfile_str(panda_parse_string(args, "mem", "mem"));
    cpufile = panda_parse_string(args, "cpu", "cpu");
    interrupt = panda_parse_bool(args, "interrupt");
    fiq = panda_parse_bool(args, "fiq");
    feed_null = panda_parse_bool(args, "null");
    auto_enum = panda_parse_bool(args, "auto");
    ioreplay_debug = panda_parse_bool(args, "debug");
    limit_trace = panda_parse_bool(args, "tracelimit");
    tracedir = panda_parse_string(args, "tracedir", "../log/trace");
    const char *_trace_start_str = panda_parse_string(args, "start", "0");
    trace_start = strtoul(_trace_start_str, NULL, 10);
    trace_count = trace_start;
    nosvc = panda_parse_bool(args, "nosvc");
    enum_l1 = panda_parse_bool(args, "enuml1");
    enum_l2 = panda_parse_bool(args, "enuml2");
    enum_l3 = panda_parse_bool(args, "enuml3");
    enum_l4 = panda_parse_bool(args, "enuml4");
    prepare_hwirq_l1(l1_nums, args, "l1", enum_l1);
    prepare_hwirq(l2_nums, args, "l2", enum_l2);
    prepare_hwirq(l3_nums, args, "l3", enum_l3);
    prepare_hwirq(l4_nums, args, "l4", enum_l4);
    init_calibrate = panda_parse_bool(args, "calib");
    compact_output = panda_parse_bool(args, "pack");
    // No auto blacklist for first and last layer
    if (panda_parse_bool(args, "blacklist")) {
        if (enum_l4)
            l3_blacklist = true;
        if (enum_l3)
            l2_blacklist = true;
    }
    const char *_replay_log = panda_parse_string(args, "replay", "");
    if (_replay_log[0])
        load_replay_log(_replay_log);
    quickdedup = panda_parse_bool(args, "dedup");
    const char *_timer_io_list = panda_parse_string(args, "iolist", "");
    if (_timer_io_list[0])
        load_timer_io(_timer_io_list);
    clear_irq = panda_parse_bool(args, "clearirq");

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

    panda_disable_tb_chaining();

    start = time(NULL);

    return true;
}

void uninit_plugin(void *self) { }
