# Automated Rehosting

This document aims to describe some of the theory behind how this project works (or
at least how it's _supposed_ to work).


## Overview

The project is divided into two main parts:

1. The Python "master"
2. The QEMU "runner"

The Python side of the project is responsible for making high-level decisions about
how to interpret the results the runners are getting. This includes adding new
virtual devices (really just memory regions), sharing new knowledge between the
runners, and persisting state so that it can be restored if a bad path is explored.


## The Master

Repo: https://github.com/computerfreak/auto-emulation2-master

The master is composed of two parts:

1. The main thread responsible for spawning runners and interpreting results
2. The runner handler threads responsible for communicating with the runners


### Main thread

The main thread sets everything up (loads vmlinux, kernel elf, initrd, extracts
kallsyms, etc.) and then starts a `ThreadingTCPServer` which creates a `QEMUHandler`
for each incoming connection.

The master groups runners together into "generations" where each generation starts
from a given state and tries to find something which causes emulation to progress further.
We group runners together like this so that we can efficiently distribute a workload in the
case that a specific value needs to be found for emulation to progress. For example, a
device driver may spin waiting for a certain bit to flip in a status register and
we need to automatically find which bit it is. Instead of running 32 different runners
in series, we can create 32 runners at once in the same generation and run them all
simultaneously.

After all runners in a generation have completed, the main analysis routine begins.

The analysis first iterates over all "new" memory accesses from the run and either creates
a new device (Python emulated or QEMU provided) or notifies the appropriate existing device
about the new access.

After all memory accesses have been processed, the second stage kicks in which tries
to determine if the emulation has stalled at a certain point (i.e. there haven't been any
new devices created or significant memory accesses in the past couple generations).
If the last two generations are identical, the analysis examines the call trace and
tries to determine if QEMU is timing out due to a spin loop waiting on something to initialize,
or if the kernel has `panic()`d due to a device driver failing to initialize.

In theory, the kernel will almost never get stuck in a spin loop as the `rehost` plugin
throws random values back for all new `read`s, and one of those is likely to flip the bit
needed to continue after only around 16 iterations. In the event that the analyzer detects
we've gotten stuck though, it determines the address being spun on and then
sets up the next generation of runners to try specific combinations to narrow down
what value needs to be returned for emulation to progress. Once a specific value has been found,
the old memory accesses for that address are collapsed down so that only the "correct" value
is returned.

In the more likely event that the kernel has panicked, the analyzer walks up the callstack
at the time QEMU exited until it hits a function that isn't in a normal `panic()` callstack.
It then adds that function to the list of things to NOP out and continues. If the next
generation crashes again and the crashing callstack is similar (currently >70% the same
but this metric needs to be improved), the next function up the callstack is NOP'd out.
This continues until either we've hit the top of the callstack and nothing works (bad) or
we've found the correct function to NOP out and execution continues (good!).


## The Runner

The runner consists of two main things right now:

1. The `rehosting` machine definition
2. The `rehost` PANDA plugin


### `rehosting` - The QEMU Machine

In addition to a few QEMU changes, a custom QEMU machine definition was created
for this project called `rehosting`. Its job is to parse the additional
command-line options specifying:

* The memory map
* The machine ID (board-id)

The memory map is used to instantiate QEMU-provided implementations of common devices.
For example, if we detect that an ARM Generic Interrupt Controller (GIC) should be
located at 0x20000000, that information is passed to the machine through this memory
map and QEMU's built-in implementation of the GIC is used.

The board ID is used by Linux kernels which expect ATAGs (instead of a DTB) at boot.


### `rehost` - The PANDA Plugin
The second (and main) part of the runner is implemented as a PANDA plugin
called `rehost`. The plugin is responsible for hooking specific functions
in the Linux kernel which allows it to keep an internal state on what device
type was most recently measured. Along with this function hooking, unassigned
memory reads/writes are intercepted by the plugin. These two data points combined
allows the plugin to guess what type of device lives where. This information is
then passed along to the master which adds it to the master state it keeps
internally, and this master state is passed to any future QEMU runners in the hope that
they may be able to use that information to progress further in the boot process.

The plugin also maintains a complete call tree of kernel execution (with help
from the `callstack_instr` plugin provided with PANDA), and this is passed back
to the master for analysis to determine if a certain function is spinning, a certain
function is constantly crashing emulation, etc.

## Communication Between Master and Runners

The master and runners talk back and forth over a very simple protocol using protobuf at its core.
When the runner is started, it connect back to the master server which then
forks to handle this particular session.

When the runner first connect back, the master sends it everything the runner will need
to know to run. This includes:

* The symbol table (so named hooks in the plugin can be translated to addresses).
* The old known memory accesses so the runner knows how to respond to accesses.
* A list of functions to NOP/skip over.

The runner then begins emulation, notifying the master whenver a new memory access is encountered.

After emulation ends (whether from some halt function being called in the kernel or
QEMU timing out), the plugin sends back the final call tree as well as the accumulated
guest log (created by hooking `emit_log_char`).
