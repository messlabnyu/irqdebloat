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

extern "C" {

bool init_plugin(void *);
void uninit_plugin(void *);

}

/*
(gdb) print (int)&((struct irq_desc*)0)->action
$1 = 52
(gdb) print (int)&((struct irqaction*)0)->handler
$2 = 0
(gdb) break *0xc018407c
Breakpoint 1 at 0xc018407c: file /usr/src/kernel/kernel/irq/irqdesc.c, line 643.
*/

FILE *outf;

#define IRQ_ACTION_OFF 0x34

static int before_block_exec(CPUState *cpu, TranslationBlock *tb) {
#ifdef TARGET_ARM
    CPUARMState *envp = (CPUARMState *)((CPUState *)cpu->env_ptr);
    if (tb->pc != 0xc018407c) return 0;
    target_ulong irq_desc_ptr = envp->regs[0];
    target_ulong irq_action_ptr = 0;
    panda_virtual_memory_read(cpu, irq_desc_ptr+IRQ_ACTION_OFF, (uint8_t *)&irq_action_ptr, sizeof(target_ulong));
    target_ulong action = 0;
    panda_virtual_memory_read(cpu, irq_action_ptr, (uint8_t *)&action, sizeof(target_ulong));
    fprintf(outf, "Found irq_desc at " TARGET_FMT_lx " irqaction " TARGET_FMT_lx " action " TARGET_FMT_lx "\n",
        irq_desc_ptr, irq_action_ptr, action);
    //exit(0);
#endif
    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    panda_arg_list *args = panda_get_args("printhandler");
    const char *name = panda_parse_string_req(args, "out", "name of the output file");
    outf = fopen(name, "w");

    return true;
}

void uninit_plugin(void *self) {
    fclose(outf);
}
