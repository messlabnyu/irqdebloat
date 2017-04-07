/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Nick Gregory    ngregory@nyu.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#define __STDC_FORMAT_MACROS

#include <iostream>
#include <string>
#include <unordered_map>
#include <map>
#include <vector>
#include <algorithm>
#include <time.h>
#include <fstream>
#include <sstream>

#include "rehost.h"

extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}


// State tracking
device_t last_device = UNKNOWN_DEVICE;
clock_t last_device_time = 0;


/*
 * Guest function hooks
 */

bool set_last_device(device_t type)
{
    last_device = type;
    last_device_time = clock();

    return 0;
}

bool print_hook(CPUState *cpu, TranslationBlock *tb)
{
    uint8_t buf[1024];
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    target_ulong str_ptr = env->regs[0]; // TODO: Architecture neutral

    panda_virtual_memory_read(cpu, str_ptr, buf, sizeof(buf));

    printf("%s", buf);
    
    return 0;
}

bool poweroff_hook(CPUState *cpu, TranslationBlock *tb)
{
    DEBUG("Machine should restart or shutdown now.");
    
    return 0;
}

/*
 * List of addresses that have already been patched by the skip function.
 * We need to keep this to prevent an endless loop of exec->re-translate->exec->...
 * We can't write all of these at load time because things may not be loaded/decompressed yet.
 * We only care about things in kernel-land right now so there's no chance we'll have a
 *  virtual address overlap issue.
 */
std::vector<target_ulong> patched_funcs;

// mov r0, #0; bx lr
// TODO: architecture-independent
uint8_t patch_asm[] = {0x00, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1};

bool skip_func(CPUState *cpu, TranslationBlock *tb)
{
    target_ulong addr = tb->pc;

    if (std::find(patched_funcs.begin(), patched_funcs.end(), addr) == patched_funcs.end()) {
        DEBUG("Patching function at 0x" TARGET_FMT_lx, addr);
        panda_virtual_memory_write(cpu, addr, patch_asm, sizeof(patch_asm));
        patched_funcs.push_back(addr);
        return 1;
    } else {
        return 0;
    }
}


/*
 * Plugin-wide maps
 */

std::unordered_map<target_ulong, std::vector<hook_func_t>> hooks;
std::map<std::string, target_ulong> kallsyms;
std::map<std::string, hook_func_t> readable_hooks = {
    {"printk", print_hook},
    {"printascii", print_hook},
    {"init_IRQ", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(INTERRUPT_CONTROLLER_DIST);
        }
    },
    {"gic_cpu_init", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(INTERRUPT_CONTROLLER_CPU);
        }
    },
    {"uart_register_driver", [](CPUState *cpu, TranslationBlock *tb)
        {
            return set_last_device(UART_DEVICE);
        }
    },
    {"die", poweroff_hook},
    {"machine_restart", poweroff_hook},
};


/*
 * PANDA callback functions
 */

bool before_block_exec_invalidate_opt(CPUState *cpu, TranslationBlock *tb)
{
    int ret = 0;

    auto func_hooks = hooks.find(tb->pc);
    if (func_hooks != hooks.end()) {
        for (auto &hook : func_hooks->second) {
            ret |= (*hook)(cpu, tb);
        }
    }

    if (ret)
        DEBUG("Invalidating the translation block at 0x" TARGET_FMT_lx, tb->pc);

    return ret;
}

int check_unassigned_mem_r(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size)
{
    MemoryRegion *subregion;
    
    QTAILQ_FOREACH(subregion, &cpu->memory->subregions, subregions_link) {
        if (addr >= subregion->addr && addr < subregion->addr + subregion->size) {
            // addr is in a defined memory region, so just let QEMU process it as normal
            return 0;
        }
    }

    // This memory read is not in any existing MemoryRegion, so report it to the master

    DEBUG("Unassigned read at 0x" TARGET_FMT_lx, addr);
    DEBUG("Current last device: %u set at time %lu", last_device, last_device_time);
    
    return 0;
}

int check_unassigned_mem_w(CPUState *cpu, target_ulong pc, target_ulong addr,
                           target_ulong size, void *buf)
{
    MemoryRegion *subregion;
    
    QTAILQ_FOREACH(subregion, &cpu->memory->subregions, subregions_link) {
        if (subregion->addr <= addr && addr < subregion->addr + subregion->size) {
            return 0;
        }
    }

    DEBUG("Unassigned write at 0x" TARGET_FMT_lx, addr);
    DEBUG("Current last device: %u set at time %lu", last_device, last_device_time);

    last_device = UNKNOWN_DEVICE;
    
    return 0;
}


/*
 * Plugin initialization
 */

void parse_sym_file(const char *sym_file)
{
    std::ifstream file(sym_file);
    std::string line;
    int count = 0;

    // Parse out the symbol file (0xaddraddr T func_name)
    while (std::getline(file, line)) {
        std::stringstream linestream(line);
        target_ulong addr;
        std::string sym_name;

        linestream >> std::hex >> addr;
        linestream.ignore(3); // Ignore ' T '
        getline(linestream, sym_name, ' ');
        kallsyms[sym_name] = addr;
        count++;
    }

    std::cout << "Parsed " << count << " symbols from " << sym_file << std::endl;

    // Use the new symbol table to transform readable_hooks into hooks
    for (auto hook = readable_hooks.begin(); hook != readable_hooks.end(); hook++) {
        auto symbol = kallsyms.find(hook->first);
        if (symbol != kallsyms.end()) {
            auto sym_addr = symbol->second;
            auto hook_func = hook->second;
            hooks[sym_addr].push_back(hook_func);
        } else {
            std::cout << "WARNING: Function " << hook->first << " not in kallsyms" << std::endl;
        }
    }
}

bool init_plugin(void *self)
{
    panda_cb cb;
    panda_arg_list *args;
    const char *sym_file;

    // May not be necessary but to afraid that not having this will silently break stuff
    panda_disable_tb_chaining();
    cb.before_block_exec_invalidate_opt = before_block_exec_invalidate_opt;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC_INVALIDATE_OPT, cb);
   
    panda_enable_memcb();
    cb.virt_mem_before_read = check_unassigned_mem_r;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, cb);
    cb.virt_mem_before_write = check_unassigned_mem_w;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, cb);

    args = panda_get_args("rehost");
    
    sym_file = panda_parse_string_req(args, "sym_file", "File path of kallsyms dump");
    parse_sym_file(sym_file);

    panda_free_args(args);

    return true;
}

void uninit_plugin(void *self)
{
    // TODO: Dump new things to master
}
