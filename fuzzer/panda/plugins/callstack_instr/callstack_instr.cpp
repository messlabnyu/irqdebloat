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
#define __STDC_FORMAT_MACROS

#include <cstdio>
#include <cstdlib>

#include <unordered_map>
#include <set>
#include <unordered_set>
#include <vector>
#include <algorithm>

#include <capstone/capstone.h>
#if defined(TARGET_I386)
#include <capstone/x86.h>
#elif defined(TARGET_ARM)
#include <capstone/arm.h>
#elif defined(TARGET_PPC)
#include <capstone/ppc.h>
#endif

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "callstack_instr.h"

extern "C" {
#include "panda/plog.h"

#include "callstack_instr_int_fns.h"

bool translate_callback(CPUState* cpu, target_ulong pc);
int exec_callback(CPUState* cpu, target_ulong pc);
int before_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_exec(CPUState* cpu, TranslationBlock *tb);
int after_block_translate(CPUState* cpu, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);

PPP_PROT_REG_CB(on_call);
PPP_PROT_REG_CB(on_ret);

}

PPP_CB_BOILERPLATE(on_call);
PPP_CB_BOILERPLATE(on_ret);

enum instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
};

struct stack_entry {
    target_ulong pc;
    target_ulong sp;
    instr_type kind;
};

#define MAX_STACK_DIFF 5000

csh cs_handle_32;
csh cs_handle_64;

// Track the different stacks we have seen to handle multiple threads
// within a single process.
std::unordered_map<target_ulong,std::set<target_ulong>> stacks_seen;

// Use a typedef here so we can switch between the stack heuristic and
// the original code easily
#ifdef USE_STACK_HEURISTIC
typedef std::pair<target_ulong,target_ulong> stackid;
target_ulong cached_sp = 0;
target_ulong cached_asid = 0;
#else
typedef target_ulong stackid;
#endif

// stackid -> shadow stack
std::unordered_map<stackid, std::vector<stack_entry>> callstacks;
// stackid -> function entry points
std::unordered_map<stackid, std::vector<target_ulong>> function_stacks;
// EIP -> instr_type
std::unordered_map<target_ulong, instr_type> call_cache;
int last_ret_size = 0;

// List of known functions that we always mark a call when we see run
std::unordered_set<target_ulong> known_functions;


static inline bool in_kernelspace(CPUArchState* env) {
#if defined(TARGET_I386)
    return ((env->hflags & HF_CPL_MASK) == 0);
#elif defined(TARGET_ARM)
    return ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_SVC);
#else
    return false;
#endif
}

static inline target_ulong get_stack_pointer(CPUArchState* env) {
#if defined(TARGET_I386)
    return env->regs[R_ESP];
#elif defined(TARGET_ARM)
    return env->regs[13];
#else
    return 0;
#endif
}

static stackid get_stackid(CPUArchState* env) {
#ifdef USE_STACK_HEURISTIC
    target_ulong asid;

    // Track all kernel-mode stacks together
    if (in_kernelspace(env))
        asid = 0;
    else
        asid = panda_current_asid(ENV_GET_CPU(env));

    // Invalidate cached stack pointer on ASID change
    if (cached_asid == 0 || cached_asid != asid) {
        cached_sp = 0;
        cached_asid = asid;
    }

    target_ulong sp = get_stack_pointer(env);

    // We can short-circuit the search in most cases
    if (std::abs(sp - cached_sp) < MAX_STACK_DIFF) {
        return std::make_pair(asid, cached_sp);
    }

    auto &stackset = stacks_seen[asid];
    if (stackset.empty()) {
        stackset.insert(sp);
        cached_sp = sp;
        return std::make_pair(asid,sp);
    }
    else {
        // Find the closest stack pointer we've seen
        auto lb = std::lower_bound(stackset.begin(), stackset.end(), sp);
        target_ulong stack1 = *lb;
        lb--;
        target_ulong stack2 = *lb;
        target_ulong stack = (std::abs(stack1 - sp) < std::abs(stack2 - sp)) ? stack1 : stack2;
        int diff = std::abs(stack-sp);
        if (diff < MAX_STACK_DIFF) {
            return std::make_pair(asid,stack);
        }
        else {
            stackset.insert(sp);
            cached_sp = sp;
            return std::make_pair(asid,sp);
        }
    }
#else
    if (in_kernelspace(env)) {
        // Linux hack for kthreads: keep track of sp & ~2*PAGE_SIZE, since a
        // large (i.e. >2pg) change in SP means there's a different kthread running
        return panda_current_sp(ENV_GET_CPU(env)) & ~0x2000;
    } else {
        return panda_current_asid(ENV_GET_CPU(env));
    }
#endif
}

bool is_arm_call(csh handle, cs_insn *insn) {
    // Must be a jump of some kind
	if (!cs_insn_group(handle, insn, CS_GRP_JUMP)) {
		return false;
	}

    // Either needs to jump to a known function, or be a BL*
    if (insn->id == ARM_INS_BL || insn->id == ARM_INS_BLX) {
        return true;
    }

    cs_arm details = insn->detail->arm;

    if (details.operands[0].type == ARM_OP_IMM && 
            known_functions.find(details.operands[0].imm) != known_functions.end()) {
        return true;
    }

    return false;
}

instr_type disas_block(CPUArchState* env, target_ulong pc, int size) {
    size_t count;
    instr_type res = INSTR_UNKNOWN;
#if defined(TARGET_I386)
    csh handle = (env->hflags & HF_LMA_MASK) ? cs_handle_64 : cs_handle_32;
#elif defined(TARGET_ARM)
    csh handle = cs_handle_32;

    if (env->thumb){
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    }
    else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    }

#elif defined(TARGET_PPC) || defined(TARGET_MIPS)
    csh handle = cs_handle_32;
#endif

    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(ENV_GET_CPU(env), pc, buf, size, 0);
    if (err == -1) {
        printf("Couldn't read TB memory at " TARGET_FMT_lx "!\n", pc);
        goto done2;
    }

    cs_insn *insn;
    cs_insn *end;
    count = cs_disasm(handle, buf, size, pc, 0, &insn);
    if (count <= 0) goto done2;

    for (end = insn + count - 1; end >= insn; end--) {
        if (!cs_insn_group(handle, end, CS_GRP_INVALID)) {
            break;
        }
    }
    if (end < insn) goto done;

#if defined(TARGET_I386)
    if (cs_insn_group(handle, end, CS_GRP_CALL)) {
        res = INSTR_CALL;
    } else if (cs_insn_group(handle, end, CS_GRP_RET)) {
        res = INSTR_RET;
    } else {
        res = INSTR_UNKNOWN;
    }
#elif defined(TARGET_ARM)
    if (is_arm_call(handle, end)) {
        res = INSTR_CALL;
    }
    // ngregory 30 Nov. 2017: INSTR_RET doesn't do anything
    else {
        res = INSTR_UNKNOWN;
    }
#endif

done:
    cs_free(insn, count);
done2:
    free(buf);
    return res;
}

int after_block_translate(CPUState *cpu, TranslationBlock *tb) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    call_cache[tb->pc] = disas_block(env, tb->pc, tb->size);

    return 1;
}

int before_block_exec(CPUState *cpu, TranslationBlock *tb) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    std::vector<stack_entry> &v = callstacks[get_stackid(env)];
    std::vector<target_ulong> &w = function_stacks[get_stackid(env)];
    if (v.empty()) return 1;

    target_ulong cur_sp = panda_current_sp(cpu);

    if (tb->pc == 0x803d50fc) {
        printf("Return to cpu_up\n");
    }
    for (int i = v.size()-1; i >= 0; i--) {
        if (tb->pc == v[i].pc && cur_sp == v[i].sp) {
            //printf("Return to 0x" TARGET_FMT_lx " has SP 0x" TARGET_FMT_lx " at depth %d\n", tb->pc, cur_sp, i);
            PPP_RUN_CB(on_ret, cpu, w[i], tb->pc, get_stackid(env));
            v.erase(v.begin()+i, v.end());
            w.erase(w.begin()+i, w.end());

            break;
        }
    }

    return 0;
}

int after_block_exec(CPUState* cpu, TranslationBlock *tb) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    instr_type tb_type = call_cache[tb->pc];

    if (tb_type == INSTR_CALL) {
        target_ulong pc = panda_current_pc(cpu);
        target_ulong sp = panda_current_sp(cpu);

        stack_entry se = {tb->pc+tb->size, sp, tb_type};
        callstacks[get_stackid(env)].push_back(se);

        function_stacks[get_stackid(env)].push_back(pc);
        PPP_RUN_CB(on_call, cpu, pc, tb->pc + tb->size, get_stackid(env));

        //printf("Return to 0x" TARGET_FMT_lx " will have SP 0x" TARGET_FMT_lx " at depth %lu\n", tb->pc + tb->size, sp, callstacks[get_stackid(env)].size());
    }
    else if (tb_type == INSTR_RET) {
        //printf("Just executed a RET in TB " TARGET_FMT_lx "\n", tb->pc);
        //if (next) printf("Next TB: " TARGET_FMT_lx "\n", next->pc);
    }

    return 1;
}

// Public interface implementation
int get_callers(target_ulong callers[], int n, CPUState* cpu) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    std::vector<stack_entry> &v = callstacks[get_stackid(env)];
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        callers[i] = rit->pc;
    }
    return i;
}


#define CALLSTACK_MAX_SIZE 16
// writes an entry to the pandalog with callstack info (and instr count and pc)
Panda__CallStack *pandalog_callstack_create() {
    assert (pandalog);
    CPUState *cpu = first_cpu;
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    uint32_t n = 0;
    std::vector<stack_entry> &v = callstacks[get_stackid(env)];
    auto rit = v.rbegin();
    for (/*no init*/; rit != v.rend() && n < CALLSTACK_MAX_SIZE; ++rit) {
        n ++;
    }
    Panda__CallStack *cs = (Panda__CallStack *) malloc (sizeof(Panda__CallStack));
    *cs = PANDA__CALL_STACK__INIT;
    cs->n_addr = n;
    cs->addr = (uint64_t *) malloc (sizeof(uint64_t) * n);
    v = callstacks[get_stackid(env)];
    rit = v.rbegin();
    uint32_t i=0;
    for (/*no init*/; rit != v.rend() && n < CALLSTACK_MAX_SIZE; ++rit, ++i) {
        cs->addr[i] = rit->pc;
    }
    return cs;
}


void pandalog_callstack_free(Panda__CallStack *cs) {
    free(cs->addr);
    free(cs);
}



int get_functions(target_ulong functions[], int n, CPUState* cpu) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    std::vector<target_ulong> &v = function_stacks[get_stackid(env)];
    if (v.empty()) {
        return 0;
    }
    auto rit = v.rbegin();
    int i = 0;
    for (/*no init*/; rit != v.rend() && i < n; ++rit, ++i) {
        functions[i] = *rit;
    }
    return i;
}

void get_prog_point(CPUState* cpu, prog_point *p) {
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;
    if (!p) return;

    // Get address space identifier
    target_ulong asid = panda_current_asid(ENV_GET_CPU(env));
    // Lump all kernel-mode CR3s together

    if(!in_kernelspace(env))
        p->cr3 = asid;

    // Try to get the caller
    int n_callers = 0;
    n_callers = get_callers(&p->caller, 1, cpu);

    if (n_callers == 0) {
#ifdef TARGET_I386
        // fall back to EBP on x86
        int word_size = (env->hflags & HF_LMA_MASK) ? 8 : 4;
        panda_virtual_memory_rw(cpu, env->regs[R_EBP]+word_size, (uint8_t *)&p->caller, word_size, 0);
#endif
#ifdef TARGET_ARM
        p->caller = env->regs[14]; // LR
#endif

    }

    p->pc = cpu->panda_guest_pc;
}

void callstack_add_function(target_ulong addr) {
    known_functions.insert(addr);
}

Panda__CallStack *get_current_function_stack() {
    CPUState *cpu = first_cpu;
    CPUArchState* env = (CPUArchState*)cpu->env_ptr;

    std::vector<target_ulong> &v = function_stacks[get_stackid(env)];

    Panda__CallStack *cs = (Panda__CallStack *) malloc (sizeof(Panda__CallStack));
    *cs = PANDA__CALL_STACK__INIT;
    cs->n_addr = v.size();
    cs->addr = (uint64_t*) malloc(sizeof(uint64_t) * cs->n_addr);

    uint32_t i = 0;
    for (auto func : v) {
        cs->addr[i] = func;
        i++;
    }

    return cs;
}

bool init_plugin(void *self) {
#if defined(TARGET_I386)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#if defined(TARGET_X86_64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_64) != CS_ERR_OK)
        return false;
#endif
#elif defined(TARGET_ARM)
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_handle_32) != CS_ERR_OK)
        return false;
#elif defined(TARGET_PPC)
    if (cs_open(CS_ARCH_PPC, CS_MODE_32, &cs_handle_32) != CS_ERR_OK)
        return false;
#endif

    // Need details in capstone to have instruction groupings
    cs_option(cs_handle_32, CS_OPT_DETAIL, CS_OPT_ON);
#if defined(TARGET_X86_64)
    cs_option(cs_handle_64, CS_OPT_DETAIL, CS_OPT_ON);
#endif

    panda_cb pcb;

    panda_enable_memcb();
    panda_enable_precise_pc();

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
}
