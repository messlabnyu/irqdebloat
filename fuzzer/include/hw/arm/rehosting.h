#ifndef QEMU_REHOSTING_H 
#define QEMU_REHOSTING_H

#include "qemu-common.h"
#include "exec/hwaddr.h"

#define NUM_IRQS        256
#define PPI(irq)        ((irq) + 16)

#define REHOSTING_MAX_CPUS     4
#define REHOSTING_DEFAULT_RAM  1024*1024*1024

#define RAM_LIMIT_GB    4

typedef enum {
    MEM = 0,
    NAND,
    NAND_CONTROLLER,
    DMAC,
    CPUPERIPHS,
    GIC_DIST,
    GIC_CPU,
    GIC_V2M,
    GIC_ITS,
    GIC_REDIST,
    UART,
    GPIO,
    GP_TIMER0,
    GP_TIMER1,
    DG_TIMER,

    MEM_REGION_COUNT,
} MEM_TYPE;

typedef struct MemMapEntry {
    hwaddr base;
    hwaddr size;
    MEM_TYPE type;
    MemoryRegion *mr;
} MemMapEntry;


#endif
