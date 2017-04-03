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
#include <time.h>
#include <fstream>
#include <sstream>

#include "rehost.h"

extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

device_t last_device = UNKNOWN_DEVICE;
clock_t last_device_time = 0;

void set_last_device(device_t type)
{
    last_device = type;
    last_device_time = clock();
}

void print_hook(CPUState *cpu)
{
    uint8_t buf[1024];
    CPUArchState *env = (CPUArchState*)cpu->env_ptr;
    target_ulong str_ptr = env->regs[0];

    panda_virtual_memory_read(cpu, str_ptr, buf, sizeof(buf));

    printf("%s", buf);
}

void poweroff_hook(CPUState *cpu)
{
    printf("Machine should restart or shutdown\n");
}

std::unordered_map<target_ulong, hook_func_t> hooks;
std::map<std::string, target_ulong> kallsyms;

std::map<std::string, hook_func_t> readable_hooks = {
    {"printk", print_hook},
    {"printascii", print_hook},
    {"init_IRQ", [](CPUState *cpu) { set_last_device(INTERRUPT_CONTROLLER_DIST); }},
    {"gic_cpu_init", [](CPUState *cpu) { set_last_device(INTERRUPT_CONTROLLER_CPU); }},
    {"uart_register_driver", [](CPUState *cpu) { set_last_device(UART_DEVICE); }},
    {"die", poweroff_hook},
    {"machine_restart", poweroff_hook},
};

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
            hooks[symbol->second] = hook->second;
        } else {
            std::cout << "WARNING: Function " << hook->first << " not in kallsyms" << std::endl;
        }
    }
}

int before_block_exec(CPUState *cpu, TranslationBlock *tb)
{
    auto hook = hooks.find(tb->pc);
    if (hook != hooks.end()) {
        (*hook->second)(cpu);
    }

    return 0;
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

    printf("rehost: Unassigned read at 0x" TARGET_FMT_lx ". ", addr);
    printf("Current last device: %u\n", last_device);
    
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

    printf("rehost: Unassigned write at 0x" TARGET_FMT_lx ". ", addr);
    printf("Current last device: %u\n", last_device);
    
    return 0;
}

bool init_plugin(void *self)
{
    /*
     * TODO:
     *  parse board_id from dump_machine_table
     *  figure out how to control vbi->bootinfo.board_id
     */

    panda_cb cb;
    panda_arg_list *args;
    const char *sym_file;

    panda_enable_memcb();

    cb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, cb);
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
}
