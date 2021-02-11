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

#include <yaml-cpp/yaml.h>
#include <iostream>

extern "C" {

#include "panda/plugin.h"
#include "loadstate_int_fns.h"

bool init_plugin(void *);
void uninit_plugin(void *);

}

// UGH this is only defined in exec.c (used via a typedef elsewhere)
// recreate it here and NEVER PULL AGAIN
struct CPUAddressSpace {                         
    void *cpu;                               
    void *as;                            
    void *memory_dispatch;
    MemoryListener tcg_as_listener;
};

void load_states(CPUState *env, const char *memfile, const char *cpufile) {
#ifdef TARGET_ARM
    YAML::Node cpuregs = YAML::LoadFile(cpufile);
    CPUArchState *envp = (CPUArchState *)env->env_ptr;
    for (int i = 0; i < cpuregs["regs"].size(); i++) {
        printf("regs[%d] = %#x\n", i, cpuregs["regs"][i].as<uint32_t>());
        envp->regs[i] = cpuregs["regs"][i].as<uint32_t>();
    }
    printf("daif = %#x\n", cpuregs["daif"].as<uint32_t>());
    envp->daif = cpuregs["daif"].as<uint32_t>();
    printf("cp15.dacr_ns = %#x\n", cpuregs["cp15.dacr_ns"].as<uint32_t>());
    envp->cp15.dacr_ns = cpuregs["cp15.dacr_ns"].as<uint32_t>();
    printf("cp15.dacr_s = %#x\n", cpuregs["cp15.dacr_s"].as<uint32_t>());
    envp->cp15.dacr_s = cpuregs["cp15.dacr_s"].as<uint32_t>();
    printf("cp15.scr_el3 = %#x\n", cpuregs["cp15.scr_el3"].as<uint32_t>());
    envp->cp15.scr_el3 = cpuregs["cp15.scr_el3"].as<uint32_t>();
    printf("cp15.hcr_el2 = %#x\n", cpuregs["cp15.hcr_el2"].as<uint32_t>());
    envp->cp15.hcr_el2 = cpuregs["cp15.hcr_el2"].as<uint32_t>();
    printf("uncached_cpsr = %#x\n", cpuregs["uncached_cpsr"].as<uint32_t>());
    envp->uncached_cpsr = cpuregs["uncached_cpsr"].as<uint32_t>();
    if (cpuregs["features"]) {
        printf("features = %#lx\n", cpuregs["features"].as<uint64_t>());
        envp->features = cpuregs["features"].as<uint64_t>();
    }
    printf("spsr = %#x\n", cpuregs["spsr"].as<uint32_t>());
    envp->spsr = cpuregs["spsr"].as<uint32_t>();

    if (cpuregs["cp15.tpidrprw_s"]) {
        printf("cp15.tpidrprw_s = %#x\n", cpuregs["cp15.tpidrprw_s"].as<uint32_t>());
        envp->cp15.tpidrprw_s = cpuregs["cp15.tpidrprw_s"].as<uint32_t>();
    }

    if (cpuregs["cp15.cpacr_el1"]) {
        printf("cp15.cpacr_el1 = %#x\n", cpuregs["cp15.cpacr_el1"].as<uint32_t>());
        envp->cp15.cpacr_el1 = cpuregs["cp15.cpacr_el1"].as<uint32_t>();
    }

    printf("TTBR0_EL[] = { ");
    for (int i = 0; i < 4; i++){
        printf("%#x ", cpuregs["cp15.ttbr0_el"][i].as<uint32_t>());
        envp->cp15.ttbr0_el[i] = cpuregs["cp15.ttbr0_el"][i].as<uint32_t>();
    }
    printf("}\n");

    printf("TTBR1_EL[] = { ");
    for (int i = 0; i < 4; i++){
        printf("%#x ", cpuregs["cp15.ttbr1_el"][i].as<uint32_t>());
        envp->cp15.ttbr1_el[i] = cpuregs["cp15.ttbr1_el"][i].as<uint32_t>();
    }
    printf("}\n");

    printf("SCTLR_EL[] = { ");
    for (int i = 0; i < 4; i++){
        printf("%#x ", cpuregs["cp15.sctlr_el"][i].as<uint32_t>());
        envp->cp15.sctlr_el[i] = cpuregs["cp15.sctlr_el"][i].as<uint32_t>();
    }
    printf("}\n");

    printf("VBAR_EL[] = { ");
    for (int i = 0; i < 4; i++){
        printf("%#x ", cpuregs["cp15.vbar_el"][i].as<uint32_t>());
        envp->cp15.vbar_el[i] = cpuregs["cp15.vbar_el"][i].as<uint32_t>();
    }
    printf("}\n");

    printf("banked_spsr[] = { ");
    for (int i = 0; i < 8; i++){
        printf("%#x ", cpuregs["banked_spsr"][i].as<uint32_t>());
        envp->banked_spsr[i] = cpuregs["banked_spsr"][i].as<uint32_t>();
    }
    printf("}\n");

    printf("banked_r13[] = { ");
    for (int i = 0; i < 8; i++){
        printf("%#x ", cpuregs["banked_r13"][i].as<uint32_t>());
        envp->banked_r13[i] = cpuregs["banked_r13"][i].as<uint32_t>();
    }
    printf("}\n");

    printf("banked_r14[] = { ");
    for (int i = 0; i < 8; i++){
        printf("%#x ", cpuregs["banked_r14"][i].as<uint32_t>());
        envp->banked_r14[i] = cpuregs["banked_r14"][i].as<uint32_t>();
    }
    printf("}\n");

    // Extremely gross but let's force the secure and non-secure AS
    // to have the same memory dispatcher
    if (env->num_ases > 1)
        env->cpu_ases[0].memory_dispatch = env->cpu_ases[1].memory_dispatch;

    //LOAD MEM
    FILE *fp_mem;
    unsigned char buf[0x1000];
    fp_mem = fopen(memfile,"r");
    assert(fp_mem);
    printf ("Loading RAM image at %" HWADDR_PRIx " size %" HWADDR_PRIx "\n",
            ram_start, ram_size);
    for (hwaddr a = ram_start; a < ram_start+ram_size; a += 0x1000) {
        int n = fread(buf,1,0x1000,fp_mem);
        if (-1 == n) exit(1);
#if 0
        printf("Debug: hexdump of %d bytes of RAM:\n", n);
        for (int i = 0; i < 0x1000; i += 16) {
            printf("%08lx ", a+i);
            for (int j = 0; j < 16; j++) {
                printf("%02x ", buf[i+j]);
            }
            printf("\n");
        }
#endif
        panda_physical_memory_rw(a, (uint8_t *)buf, n, 1);
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
