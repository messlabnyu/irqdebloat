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
#include "hw/arm/rehosting.h"

bool init_plugin(void *);
void uninit_plugin(void *);

extern GArray *rehosting_memmap;
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
    load_states_multi(env, &memfile, 1, cpufile);
}

void load_states_multi(CPUState *env, const char **pmemfiles, int num, const char *cpufile) {
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

    if (cpuregs["cp15.tcr_el"]) {
        printf("TCR_EL[] = { ");
        for (int i = 0; i < 4; i++){
            printf("%#x ", cpuregs["cp15.tcr_el"][i].as<uint32_t>());
            uint64_t tcr = cpuregs["cp15.tcr_el"][i].as<uint32_t>();
            envp->cp15.tcr_el[i].raw_tcr = tcr;
            envp->cp15.tcr_el[i].mask = ~(((uint32_t)0xffffffffu) >> (tcr&7));
            envp->cp15.tcr_el[i].base_mask = ~((uint32_t)0x3fffu >> (tcr&7));
        }
        printf("}\n");
    }

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

    if (cpuregs["cp15.tpidr_el"]) {
        printf("TPIDR_EL[] = {");
        for (int i = 0; i < 4; i++){
            printf("%#x ", cpuregs["cp15.tpidr_el"][i].as<uint32_t>());
            envp->cp15.tpidr_el[i] = cpuregs["cp15.tpidr_el"][i].as<uint32_t>();
        }
        printf("}\n");
    }

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

#elif defined(TARGET_MIPS)
    YAML::Node cpuregs = YAML::LoadFile(cpufile);
    CPUArchState *envp = (CPUArchState *)env->env_ptr;
    for (int i = 0; i < 32; i++) {
        printf("regs[%d] = %#x\n", i, cpuregs["regs"][i].as<uint32_t>());
        envp->active_tc.gpr[i] = cpuregs["regs"][i].as<uint32_t>();
    }
    printf("Lo = %#x\n", cpuregs["lo"].as<uint32_t>());
    envp->active_tc.LO[0] = cpuregs["lo"].as<uint32_t>();
    printf("Hi = %#x\n", cpuregs["hi"].as<uint32_t>());
    envp->active_tc.HI[0] = cpuregs["hi"].as<uint32_t>();
    printf("PC = %#x\n", cpuregs["pc"].as<uint32_t>());
    envp->active_tc.PC = cpuregs["pc"].as<uint32_t>();

    printf("Status = %#x\n", cpuregs["status"].as<uint32_t>());
    envp->CP0_Status = cpuregs["status"].as<uint32_t>();
    printf("BadVaddr = %#x\n", cpuregs["badvaddr"].as<uint32_t>());
    envp->CP0_BadVAddr = cpuregs["badvaddr"].as<uint32_t>();
    printf("Cause = %#x\n", cpuregs["cause"].as<uint32_t>());
    envp->CP0_Cause = cpuregs["cause"].as<uint32_t>();
    if (cpuregs["context"]) {
    	printf("Context = %#x\n", cpuregs["context"].as<uint32_t>());
    	envp->CP0_Context = cpuregs["context"].as<uint32_t>();
    }
#endif

    //LOAD MEM
    std::vector<const char*> memfiles(pmemfiles, pmemfiles+num);
    for (int i = 0; i < memfiles.size(); i++) {
    FILE *fp_mem;
    unsigned char buf[0x1000];
    fp_mem = fopen(memfiles[i],"r");
    assert(fp_mem);
    hwaddr memstart = ram_start;
    hwaddr memsize = ram_size;
    if (rehosting_memmap && i < rehosting_memmap->len) {
        MemMapEntry *ment = g_array_index(rehosting_memmap,MemMapEntry*,i);
        memstart = ment->base;
        memsize = ment->size;
    }
    printf ("Loading RAM image at %" HWADDR_PRIx " size %" HWADDR_PRIx "\n",
            memstart, memsize);
    for (hwaddr a = memstart; a < memstart+memsize; a += 0x1000) {
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
    fclose(fp_mem);
    }
}

bool init_plugin(void *self) {
#if defined(TARGET_ARM) || defined(TARGET_MIPS)
    return true;
#else
    return false;
#endif
}

void uninit_plugin(void *self) { }
