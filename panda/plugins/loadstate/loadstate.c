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
#include "loadstate_int_fns.h"

bool init_plugin(void *);
void uninit_plugin(void *);

void load_states(CPUState *env, const char *memfile) {
#ifdef TARGET_ARM
    // Values taken from a running Raspberry Pi using
    // a kernel module that dumped the CPU state.
    CPUArchState *envp = (CPUArchState *)env->env_ptr;
    envp->regs[0] = 0x00000003;
    envp->regs[1] = 0x54b113b0;
    envp->regs[2] = 0x00000000;
    envp->regs[3] = 0x00000002;
    envp->regs[4] = 0x8edbfb00;
    envp->regs[5] = 0x54b23000;
    envp->regs[6] = 0x7ece2838;
    envp->regs[7] = 0x0000017b;
    envp->regs[8] = 0x54b113b0;
    envp->regs[9] = 0x00000002;
    envp->regs[10] =0x54b0d20c;
    envp->regs[11] =0x00000000;
    envp->regs[12] =0x7ece2670;
    //envp->regs[13] =0x7ece2660;
    //envp->regs[13] =0xae573dac;
    envp->regs[13] =0x80b01f70;
    envp->regs[14] =0x54b060ac;
    envp->regs[15] =0x76ef9c40;
    envp->daif = 0x340;
    envp->cp15.dacr_ns = 0x17 | (3 << (3*2));
    for(int i=0; i<4; i++){
        //envp->cp15.ttbr0_el[i] = 0x3921006a;
        //envp->cp15.ttbr1_el[i] = 0x0000406a;
        //envp->cp15.sctlr_el[i] = 0x2001;
        envp->cp15.ttbr0_el[i] = 0x3a2ac06a;
        envp->cp15.ttbr1_el[i] = 0x0000406a;
        envp->cp15.sctlr_el[i] = 0x10c5387d;
    }
    // TTBR[0] = 2e07c06a TTBR[1] = 0000406a TTBR_Control = 00000000
    // SCTLR = '0b10000000000001' = 0x2001

    //load_cpustate("rpi2.cpu");

    //LOAD MEM
    FILE *fp_mem;
    char buf[0x1000];
    fp_mem = fopen(memfile,"r");
    assert(fp_mem);
    for (hwaddr a = 0; a < ram_size; a += 0x1000) {
        if (-1 == fread(buf,1,0x1000,fp_mem)) exit(1);
        panda_physical_memory_rw(a, (uint8_t *)buf, 0x1000, 1);
    }
#endif
}

bool init_plugin(void *self) {
#ifdef TARGET_ARM
    return true;
#else
    return false;
#endif
}

void uninit_plugin(void *self) { }
