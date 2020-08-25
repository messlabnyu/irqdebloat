# IRQFuzzer: Fuzzing to Enumerate IRQs

The goal of this code is to fuzz the interrupt handling code of an embedded device, with the goal of identifying valid IRQ handlers for individual peripherals. This could be used either for reverse engineering (to help identify what peripherals are on the system) or for debloating, by rewriting the firmware to replace unwanted interrupt handlers with stubs that just return, ignoring the interrupt.

The basic technique is fairly generic, and could also be used to fuzz things other than interrupt handling, such as driver code that uses MMIO. This would basically just involve setting up the CPU state so that execution starts at the function you want to fuzz, and telling `iofuzz2` not to start by triggering an interrupt.

## Interrupt Fuzzing - Example

To fuzz interrupts of an emulated ARM machine from a Raspberry Pi 2 snapshot:

```
arm-softmmu/qemu-system-arm -machine rehosting,mem-map="MEM 0x00000000-0x3f000000" \
                            -panda iofuzz2:mem=snapshots/raspi2_2.mem,cpu=snapshots/raspi2_2.yaml,timeout=32,ncpu=32,dir=raspi2irq \
                            -display none -cpu cortex-a7
```

The arguments here are:

* `mem`: the RAM snapshot
* `cpu`: the dump of CPU registers in YAML format
* `timeout`: the number of seconds to run each fuzz test case; it will also terminate if enough basic blocks are encountered without uncovering new code (to detect infinite loops)
* `ncpu`: the number of concurrent fuzz processes to run. Usually I set this to `num_cpu * 2`.
* `dir`: the directory where fuzzing results should be saved

You can also use the boolean `fiq` option to trigger FIQs. On ARM, FIQs (``Fast`` IRQs) are basically like IRQs, but have higher priority and use a different exception vector (0xffff001c instead of 0xffff0018).

This will produce output files at `./raspi2irq/`, whose filenames and contents indicate successful fuzz values and reached memory addresses, respectively.

## Supported Machines

Currently supported machines can be found in the `snapshots` directory. Each consists of a `.yaml` file with the CPU registers needed for emulation, a `.mem` file containing a memory snapshot, and a `.cmdline` giving the full command line needed to start a fuzzing session. Right now we support:

1. Beaglebone (original white), based on the TI Am335x SoC. State captured via JTAG from a real device.
2. Romulus BMC, based on the ASPEED AST2500 SoC. State captured from QEMU.
3. Raspberry Pi 2, based on the Broadcom BCM2836 SoC. State captured from QEMU.

Note that these are all some version of Linux. It would be nice to have a non-Linux OS in the mix to demonstrate generality. Maybe the Canon cameras using Magic Lantern's 

## Supporting a New Machine

To fuzz a new machine, you need to capture its CPU and RAM state, and know what range of physical memory RAM occupies (everything else will be assumed to be MMIO. Currently this can be done over JTAG or (if the target is emulated in QEMU) by attaching gdb. When capturing from QEMU, you should be careful to note that the version of QEMU used by `irqfuzzer` is likely different. In particular, the ARM feature bits may change between releases of QEMU; see `gdb_scripts/qemu_feature_convert.py` for an example of how to do this. The `arm_features` enum can be found in `target/arm/cpu.h`.

### QEMU Capture

Run your target in QEMU, and switch to the monitor (^A c). Then use `pmemsave` to dump the physical memory to a file.

To collect registers, attach to the QEMU process with `gdb`, and then source `gdb_scripts/gdb.cmds`. At the moment, there is no script to turn these into a YAML file, so you'll have to do it by hand.

### JTAG Capture

Connect to the target using OpenOCD and halt it. Then source `jtag_scripts/cpregs.tcl` to dump the CPU registers, and run `jtag_scripts/genyaml.py` to convert them into a valid YAML file for use with `irqfuzzer`.

To capture RAM, you can use the `dump_memory` command in OpenOCD. Note that by default this uses virtual addresses; however, you can patch OpenOCD to use physical addresses instead by applying the following patch (assuming a Cortex-A target):

```diff
diff --git a/src/target/cortex_a.c b/src/target/cortex_a.c
index b3a8a41d..a1e9e145 100644
--- a/src/target/cortex_a.c
+++ b/src/target/cortex_a.c
@@ -2449,21 +2449,21 @@ static int cortex_a_read_phys_memory(struct target *target,
    return retval;
 }
-static int cortex_a_read_memory(struct target *target, target_addr_t address,
-   uint32_t size, uint32_t count, uint8_t *buffer)
-{
-   int retval;
-
-   /* cortex_a handles unaligned memory access */
-   LOG_DEBUG("Reading memory at address " TARGET_ADDR_FMT "; size %" PRId32 "; count %" PRId32,
-       address, size, count);
-
-   cortex_a_prep_memaccess(target, 0);
-   retval = cortex_a_read_cpu_memory(target, address, size, count, buffer);
-   cortex_a_post_memaccess(target, 0);
-
-   return retval;
-}
+//static int cortex_a_read_memory(struct target *target, target_addr_t address,
+// uint32_t size, uint32_t count, uint8_t *buffer)
+//{
+// int retval;
+//
+// /* cortex_a handles unaligned memory access */
+// LOG_DEBUG("Reading memory at address " TARGET_ADDR_FMT "; size %" PRId32 "; count %" PRId32,
+//     address, size, count);
+//
+// cortex_a_prep_memaccess(target, 0);
+// retval = cortex_a_read_cpu_memory(target, address, size, count, buffer);
+// cortex_a_post_memaccess(target, 0);
+//
+// return retval;
+//}
 static int cortex_a_write_phys_memory(struct target *target,
    target_addr_t address, uint32_t size,
@@ -3075,7 +3075,7 @@ struct target_type cortexa_target = {
    .get_gdb_arch = arm_get_gdb_arch,
    .get_gdb_reg_list = arm_get_gdb_reg_list,
-   .read_memory = cortex_a_read_memory,
+   .read_memory = cortex_a_read_phys_memory,
    .write_memory = cortex_a_write_memory,
    .read_buffer = cortex_a_read_buffer,
```

## Fuzzing Notes

Currently the fuzzer is a simple generational fuzzer, where each generation is a single MMIO read. The fuzzer generates:

1. `genconst`: Likely constants, like 0, 0xffffffff, 0x0f0f0f0f, etc.
2. `genwin`: Sliding windows of all-ones patterns. , e.g. 1, 10, 100, ..., 11, 110, 1100, ...
3. `genint`: Integers from 0-255.
3. `genrand`: Random values (from /dev/urandom).

During each run it collects the set of MMIO addresses seen as well as edge coverage. Seeds with new coverage are then used as the basis for the next generation.

Since there is no persistent state, the fuzzer can (and does) try many values simultaneously by calling `fork()` to create up to `ncpu` processes (as specified in the `iofuzz2` options). Coverage results are communicated back to the parent over a socket. (TODO: shared memory might be faster)

## Identifying Interrupt Handlers

This is currently an open research problem. The best approach I've found so far is to align the traces from different fuzzing attempts and then look for a point where they first diverge. The usual interrupt flow is: query the interrupt controller for the hardware IRQ, translate the hardware IRQ into a system specific IRQ number, look up the corresponding handler, call the handler via a function pointer. Since the only nondeterminism in the traces are the fuzzed MMIO values, this ``fan-out'' pattern usually indicates the point where the final dispatch into the IRQ handler occurs.

A more sophisticated approach to this would be to use some kind of [differential slicing](http://bitblaze.cs.berkeley.edu/diffslicing.html) to precisely identify the divergences caused by the MMIO values.

## Dynamic Interrupt Slicing

[Note: this was previously attempted as a way to identify interrupt handlers, by looking for indirect jumps that depended on MMIO values. However, at least with the Linux kernel this doesn't work very well, because the IRQ handlers are stored in a fairly complex data structure (a radix tree) and several function pointers aside from the actual handler end up being dependent on MMIO according to the slice.]

To obtain a dynamic interrupt slice:

1. Use ioreplay and create a pandalog

```
arm-softmmu/qemu-system-arm -machine rehosting,mem-map="MEM 0x00000000-0x3f000000"            `# Use rehosting machine with the appropriate mem-map to emulate` \ 
                            -panda ioreplay:mem=raspi2.mem,cpu=raspi2.yaml,iovals=256         `# Use ioreplay with emulated machine's memory (.mem) and CPU (.yaml) snapshot, along with the fuzz value as iovals` \ 
                            -panda llvm_trace2 -pandalog ioreplay.plog                        `# Use llvm_trace2, create pandalog` \ 
                            -display none                                                     `# Disable QEMU display` 
```

2. Create criteria for dynamic slicing

`echo 'TGT_R0 at rr:1-100' > criteria.txt`

3. Use dynslice2 with the pandalog and the criteria

`./dynslice2 arm llvm-mod.bc ioreplay.plog criteria.txt`

4. Using slice_analyzer, obtain the LLVM slice

`./slice_analyzer llvm-mod.bc slice_report.bin`

## MMIO Taint

You can use the taint system to taint MMIO values and then print out branches and indirect jumps that depend on tainted data. Similar to dynamic slicing, this also doesn't work well for identifying interrupt handlers, because the indirect branches end up being tainted via control flow rather than direct data propagation.

Example (beaglebone):

```
arm-softmmu/qemu-system-arm -machine rehosting,mem-map="MEM 0x80000000-0x90000000" \
    -panda iotaint:mem=snapshots/beaglebone.mem,cpu=snapshots/beaglebone.yaml,iovals="e|100" \
    -display none -cpu cortex-a8
```

## Performance

Depending on the system being emulated, I get ~180 executions / second on a 32 core (64 thread) AMD Threadripper 3970X. This seems a little bit slow, but I haven't tried to do any profiling or optimization.

## Other Considerations

Systems may have multiple chained interrupt controllers; i.e., IRQ 10 on the primary interrupt controller may indicate that there is an interrupt pending on the secondary interrupt controller. We would then expect to see a two-level fan-out pattern in the collection of traces. The Raspberry Pi 2 is an example of a system that uses this approach.

Some peripherals may share a single interrupt for multiple separate devices, and then do some additional work in the IRQ handler to tell which one actually triggered the interrupt. Presumably, this looks similar to the primary/secondary interrupt controller case above.

Some peripherals may not have ``real'' interrupts at all; instead they may periodically poll devices to check for pending input. I believe that this is how USB 2.0 works; the host is obliged to poll the USB controller to check if there are any interrupts from a USB device. This case is not currently handled by `irqfuzzer`, but it's worth thinking about how it might be handled.

Other random things not considered: multicore SoCs (the Raspberry Pi 2 has 4 CPUs but we only emulate one; it seems to work fine?), other architectures (most pressingly aarch64, but it would be useful to have things like MIPS as well). Other architectures will *probably* work fine by just changing set of registers collected for the snapshot.
