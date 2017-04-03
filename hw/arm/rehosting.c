#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/sysbus.h"
#include "hw/arm/arm.h"
#include "hw/arm/primecell.h"
#include "hw/arm/rehosting.h"
#include "hw/devices.h"
#include "net/net.h"
#include "sysemu/block-backend.h"
#include "sysemu/device_tree.h"
#include "sysemu/numa.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "hw/boards.h"
#include "hw/compat.h"
#include "hw/loader.h"
#include "exec/address-spaces.h"
#include "qemu/bitops.h"
#include "qemu/error-report.h"
#include "hw/pci-host/gpex.h"
#include "hw/intc/arm_gic_common.h"
#include "kvm_arm.h"
#include "hw/smbios/smbios.h"
#include "qapi/visitor.h"
#include "standard-headers/linux/input.h"
#include "qemu/config-file.h"

/* Main board type
 */

typedef struct RehostingBoardInfo {
    struct arm_boot_info bootinfo;
    const char *cpu_model;
    const MemMapEntry *memmap;
    const int *irqmap;
    int smp_cpus;
    void *fdt;
    int fdt_size;
    uint32_t clock_phandle;
    uint32_t gic_phandle;
    uint32_t v2m_phandle;
    bool using_psci;
} RehostingBoardInfo;

typedef struct {
    MachineClass parent;
    RehostingBoardInfo *daughterboard;
} RehostingMachineClass;


#define TYPE_REHOSTING_MACHINE   MACHINE_TYPE_NAME("Rehosting")
#define REHOSTING_MACHINE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(RehostingMachineClass, obj, TYPE_REHOSTING_MACHINE)
#define REHOSTING_MACHINE_CLASS(klass) \
    OBJECT_CLASS_CHECK(RehostingMachineClass, klass, TYPE_REHOSTING_MACHINE)


#define DEBUG_REHOSTING_MACHINE

#ifdef DEBUG_REHOSTING_MACHINE
#define DEBUG(fmt, ...) \
do { fprintf(stderr, "rehosting_machine: " fmt "\n", ## __VA_ARGS__); } while (0)
#else
#define DEBUG(fmt, ...) do {} while(0)
#endif


static MemMapEntry memmap[MEM_REGION_COUNT];
// Allocate enough for both SPI and PPI IRQs
static int irqmap[NUM_IRQS + (GIC_INTERNAL * REHOSTING_MAX_CPUS)];

typedef struct {
    QEMUTimer *timer;
    int sockfd;
    qemu_irq spi[NUM_IRQS];
    qemu_irq ppi[REHOSTING_MAX_CPUS][GIC_INTERNAL];
} machine_irqs;

static void create_gic(RehostingBoardInfo *vbi, machine_irqs *irqs, int type, bool secure)
{
    DeviceState *gicdev;
    SysBusDevice *gicbusdev;
    int i;

    gicdev = qdev_create(NULL, gic_class_name());
    qdev_prop_set_uint32(gicdev, "revision", type);
    qdev_prop_set_uint32(gicdev, "num-cpu", smp_cpus);
    /* Note that the num-irq property counts both internal and external
     * interrupts; there are always 32 of the former (mandated by GIC spec).
     */
    qdev_prop_set_uint32(gicdev, "num-irq", NUM_IRQS + 32);
    qdev_prop_set_bit(gicdev, "has-security-extensions", false);
    qdev_init_nofail(gicdev);
    gicbusdev = SYS_BUS_DEVICE(gicdev);
    sysbus_mmio_map(gicbusdev, 0, vbi->memmap[GIC_DIST].base);
    sysbus_mmio_map(gicbusdev, 1, vbi->memmap[GIC_CPU].base);

    for (i = 0; i < smp_cpus; i++) {
        DeviceState *cpudev = DEVICE(qemu_get_cpu(i));
        int ppibase = NUM_IRQS + i * GIC_INTERNAL + GIC_NR_SGIS;
        int irq;

        for (irq = 0; irq < GIC_INTERNAL - GIC_NR_SGIS; irq++) {
            irqs->ppi[i][irq] = qdev_get_gpio_in(gicdev, ppibase + irq);
        }

        sysbus_connect_irq(gicbusdev, i, qdev_get_gpio_in(cpudev, ARM_CPU_IRQ));
        sysbus_connect_irq(gicbusdev, i + smp_cpus,
                           qdev_get_gpio_in(cpudev, ARM_CPU_FIQ));
    }

    for (i = 0; i < NUM_IRQS; i++) {
        irqs->spi[i] = qdev_get_gpio_in(gicdev, i);
    }
}

static void mach_rehosting_init(MachineState *machine)
{
    machine_irqs *s = g_malloc0(sizeof(machine_irqs));
    MemoryRegion *sysmem = get_system_memory();
    int gic_version = 2;
    int n;
    RehostingBoardInfo *vbi;
    MemoryRegion *ram = g_new(MemoryRegion, 1);
    bool firmware_loaded = bios_name || drive_get(IF_PFLASH, 0, 0);

    vbi = g_malloc0(sizeof(RehostingBoardInfo));
    vbi->cpu_model = machine->cpu_model;
    if (!vbi->cpu_model)
        vbi->cpu_model = "cortex-a15";

    vbi->memmap = memmap;
    vbi->irqmap = irqmap;

    // RESEARCH: TODO: is this a fair assumption?
    memmap[MEM].base = 0x40000000;
    memmap[MEM].size = 0x40000000;

    vbi->smp_cpus = smp_cpus;

    for (n = 0; n < smp_cpus; n++) {
        ObjectClass *oc = cpu_class_by_name(TYPE_ARM_CPU, vbi->cpu_model);
        Object *cpuobj;

        if (!oc) {
            error_report("Unable to find CPU definition");
            exit(1);
        }
        cpuobj = object_new(object_class_get_name(oc));
        object_property_set_bool(cpuobj, false, "has_el3", NULL); // Disable TrustZone

        if (vbi->using_psci) {
            object_property_set_int(cpuobj, QEMU_PSCI_CONDUIT_HVC,
                                    "psci-conduit", NULL);

            /* Secondary CPUs start in PSCI powered-down state */
            if (n > 0) {
                object_property_set_bool(cpuobj, true,
                                         "start-powered-off", NULL);
            }
        }

        object_property_set_link(cpuobj, OBJECT(sysmem), "memory",
                                 &error_abort);
        
        object_property_set_bool(cpuobj, true, "realized", NULL);
    }

    memory_region_allocate_system_memory(ram, NULL, "ram",
                                         machine->ram_size);
    memory_region_add_subregion(sysmem, vbi->memmap[MEM].base, ram);
    
    if (vbi->memmap[GIC_DIST].base && vbi->memmap[GIC_CPU].base) {
        create_gic(vbi, s, gic_version, false);
    }

    vbi->bootinfo.ram_size = memmap[MEM].size;
    vbi->bootinfo.kernel_filename = machine->kernel_filename;
    vbi->bootinfo.kernel_cmdline = machine->kernel_cmdline;
    vbi->bootinfo.initrd_filename = machine->initrd_filename;
    vbi->bootinfo.nb_cpus = smp_cpus;
    // RESEARCH: TODO: implement this
    vbi->bootinfo.board_id = 4200;

    vbi->bootinfo.is_linux = true;
    vbi->bootinfo.loader_start = vbi->memmap[MEM].base;
    vbi->bootinfo.firmware_loaded = firmware_loaded;

    arm_load_kernel(ARM_CPU(first_cpu), &vbi->bootinfo);
}

static void rehosting_machine_class_init(MachineClass *mc)
{
    mc->desc = "Rehosting Machine";
    mc->init = mach_rehosting_init;
    mc->max_cpus = REHOSTING_MAX_CPUS;
    mc->default_ram_size = REHOSTING_DEFAULT_RAM;
    mc->no_cdrom = true;
    mc->no_floppy = true;
    mc->no_parallel = true;
}

DEFINE_MACHINE("rehosting", rehosting_machine_class_init)
