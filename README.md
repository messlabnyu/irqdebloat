# IRQDebloat

IRQDebloat aims to automate the reverse engineering of hardware interrupt (IRQ) handlers, and gives user the option to disable the handlers they find unnecessary (or annoying).
Especially in more complicated systems, IRQ handlers are often wrapped in multiple layers of chained handlers or sugars, and loaded dynamically during bootstrap.

We first rehost the system onto [PANDA](https://panda.re). Then, we use coverage guided fuzzing to emulate and explore the interrupts. We'll then analyze the traces
 with a new sematic diff algorithm to find out the handler addresses. In the end, we patch the firmware to log and/or disable each interrupt handlers.
For more details, please refer to our paper which will also appear in Oakland S&P 2022.

# Dataset

|                   | Linux              | FreeBSD              | RiscOS                | VxWorks           | MMIO blacklist |
| Raspberry Pi      | `data/raspi/linux` | `data/raspi/freebsd` | `data/raspi/riscos`   | N/A               | `data/raspi/raspi.bl` |
| BeagleBone        | `data/beaglebone/linux` | N/A             | N/A                   | N/A               | `data/beaglebone/beagle.bl` |
| SABRE Lite        | `data/sabrelite/linux`  | N/A             | N/A                   | `data/sabrelite/vxworks` | `data/sabrelite/sabrelite.bl` |
| Samsung NURI      | `data/nuri/linux`  | N/A                  | N/A                   | N/A               | `data/nuri/nuri.bl` |
| Romulus           | `data/romulus/linux`    | N/A             | N/A                   | N/A               | `data/romulus/romulus.bl` |
| WRT54GL           | `data/wrt/linux`   | N/A                  | N/A                   | N/A               | N/A |
| SteamLink         | `data/steamlink/linux`  | N/A             | N/A                   | N/A               | N/A |

# Build

LLVM 3.3 is required to build PANDA. Make sure to install it under repo root `llvm` dir, and then 
run `fuzzer/build.sh` to build PANDA.

Trace analysis depends on [Binary Ninja](https://binary.ninja). All scripts are tested on the Headless version.
May require [Unicorn](https://www.unicorn-engine.org) on analyzing MIPS traces.

# Run

## Dump Memory && CPU

- **JTAG support**: [OpenOCD](https://github.com/HighW4y2H3ll/openocd/tree/raspi2b_v1.2), [Configs](jtag)
- **Linux Kernel Module**: [Patched LiME](https://github.com/HighW4y2H3ll/LiME)
- **QEMU dump**: `pmemsave` and `info registers`

## Explore Interrupts

- **Coverge Guided Fuzzing**: `arm-softmmu/qemu-system-arm -machine rehosting,mem-map="MEM {physical_ram_start}-{physical_ram_end}[;Mem ...]" -panda iofuzz2:mem={mem_dump}[|multi_mem_dumps],cpu={cpu_dump},timeout=32,ncpu=128,dir={output_dir} -display none -cpu {cpu_model}`

## Analyze Traces

- **Preprocessing**

  - **Find MMIO to block**: `iofuzztrace.py {trace_path} {output_dir}`
  - **Regroup MMIO sequences**: `iofuzztrace.py -l {mmio_blacklist} {trace_path} {output_dir}`
  - **Replay MMIO**: `./trace.py [romulus|beagle|linux|freebsd|riscos|sabre|vxwork|nuri|steamlink|wrt] {output_dir} {cpu_dump} {mem_dump} -r {replay_dir} [-l {mmio_blacklist}]`

- **Trace Analysis**: `./analyze/analysis.py {tracedir} {cpu_dump} {mem_dump} {outdir} [romulus|beagle|linux|freebsd|riscos|sabre|vxwork|nuri|steamlink|wrt]`

- **Postprocessing**: `./analyze/div_spectrum.py {tracedir} {cpu_dump} {mem_dump} {outdir} [romulus|beagle|linux|freebsd|riscos|sabre|vxwork|nuri|steamlink|wrt]`


## Patch Firmware

- **Firmware Patching** (Tested on RaspberryPi2)
  - **Logging**: `instrument/patch_*.py`
  - **Disable**: `instrument/disable_*.py`
(Note: [FreeBSD specific](instrument/fckbsd.py))

- **Linux Kernel Module Patching**

