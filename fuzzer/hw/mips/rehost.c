#include "qemu/osdep.h"
#include "hw/boards.h"
#include "qemu/config-file.h"
#include "hw/arm/rehosting.h"
#include "hw/mips/cpudevs.h"
#include "qapi/error.h"

GArray *rehosting_memmap = NULL;

#ifndef DEBUG
#define DEBUG(fmt, ...) \
do { fprintf(stderr, "rehosting_machine: " fmt "\n", ## __VA_ARGS__); } while (0)
#endif

static void parse_mem_map(char *map_str)
{
    if (!map_str) {
        error_report("No memory map specified!");
        return;
    }
    if (!rehosting_memmap)
        rehosting_memmap = g_array_new(false,false,sizeof(void*));

    // Format is "REGION_NAME 0xstart-0xend;..."
    char *pos = strtok(map_str, ";");
    while (pos) {
        char name[64];
        int type;
        hwaddr start, end;

        if (sscanf(pos, "%s %lx-%lx", name, &start, &end) == 3) {
            /*
             * "Dynamically" create memory regions for things that we may
             * use QEMU's implementation for
             */
            
            if (strcmp(name, "MEM") == 0)
                type = MEM;
            else if (strcmp(name, "NAND") == 0)
                type = NAND;
            else if (strcmp(name, "DMAC") == 0)
                type = DMAC;
            else if (strcmp(name, "GIC_DIST") == 0)
                type = GIC_DIST;
            else if (strcmp(name, "GIC_CPU") == 0)
                type = GIC_CPU;
            else if (strcmp(name, "GIC_V2M") == 0)
                type = GIC_V2M;
            else if (strcmp(name, "GIC_ITS") == 0)
                type = GIC_ITS;
            else if (strcmp(name, "GIC_REDIST") == 0)
                type = GIC_REDIST;
            else {
                error_report("Region '%s' doesn't exist", name);
                pos = strtok(NULL, ";");
                continue;
            }

            DEBUG("Adding region: %s @ 0x%lx-0x%lx", name, start, end);

            if (type == MEM) {
                MemMapEntry *ent = (MemMapEntry*)malloc(sizeof(MemMapEntry));
                ent->base = start;
                ent->size = end-start;
                ent->type = type;
                g_array_append_val(rehosting_memmap, ent);
            }
        } else {
            error_report("Error parsing memory region definition '%s'", pos);
        }
        pos = strtok(NULL, ";");
    }
}


static void mach_rehosting_init(MachineState *machine)
{
    MemoryRegion *sysmem = get_system_memory();
    MemoryRegion *ram = g_new(MemoryRegion, 1);

    MIPSCPU *cpu = cpu_mips_init(machine->cpu_model);
    cpu_mips_clock_init(cpu);

    parse_mem_map(machine->mem_map_str);

    for (int i = 0; i < rehosting_memmap->len; i++) {
        MemMapEntry *ment = g_array_index(rehosting_memmap,MemMapEntry*,i);
        char ramname[64] = {0};
        snprintf(ramname, 64, "ram%d", i);
        ment->mr = (MemoryRegion*)malloc(sizeof(MemoryRegion));
        memory_region_init_ram(ment->mr, NULL, ramname, ment->size, &error_fatal);
        memory_region_add_subregion(sysmem, ment->base, ment->mr);
    }
}

static void rehosting_machine_class_init(MachineClass *mc)
{
    mc->desc = "Rehosting Machine";
    mc->init = mach_rehosting_init;
}

DEFINE_MACHINE("rehosting", rehosting_machine_class_init)
