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

TODO


## The Runner

The runner consists of two main things right now:

1. The `rehosting` machine definition
2. The `rehost` PANDA plugin


### `Rehosting` - The QEMU Machine

In addition to a few QEMU changes, a custom QEMU machine definition was created
for this project called `rehosting`. Its job is to parse the additional
command-line options specifying:

* The memory map
* The machine ID (board-id)

Other than that, it is essentially identical to a stripped-down `virt` machine.


### `Rehost` - The PANDA Plugin
The second (and main) part of the runner is implemented as a PANDA plugin
called `rehost`. The plugin is responsible for hooking specific functions
in the Linux kernel which allows it to keep an internal state on what device
type was most recently measured. Along with this function hooking, unassigned
memory reads/writes are intercepted by the plugin. These two data points combined
allows the plugin to guess what type of device lives where. This information is
then passed along to the master which adds it to the master state it keeps
internally, and this master state is passed to any future QEMU runners in the hope that
they may be able to use that information to progress further in the boot process.

## Communication Between Master and Runners

TODO
