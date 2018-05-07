# Automated Rehosting

## Setup

0. Clone
1. `cd panda/plugins/rehost; protoc --proto_path=. --cpp_out=. packets.proto; cd ../../../`
2. `./panda/scripts/install_ubuntu.sh`


## Theory/overview

Theory docs with overview of algorithms used and more are [here](./THEORY.md).


## TODO

* Incorporate building packets.proto into the install script
* Automatically extract everything we need from any input format (e.g. given an ELF, extract vmlinux and initrd; given a vmlinuz and initrd, extract vmlinux, and create an ELF for QEMU)


## ARM Interrupt Fuzzing - Example

In order to fuzz interrupts of an emulated ARM machine:

``arm-softmmu/qemu-system-arm -machine rehosting,mem-map="MEM 0x00000000-0x3f000000"            `# Use rehosting machine with the appropriate mem-map to emulate` \ 
                            
                            -panda iofuzz2:mem=raspi2.mem,cpu=raspi2.yaml,timeout=32,ncpu=32  `# Use iofuzz2 with emulated machine's memory (.mem) and CPU (.yaml) snapshot` \ 
                            
                            -display none                                                     `# Disable QEMU display` ``

This will produce output files at ./irqfuzz/, whose filenames and contents indicate successful fuzz values and reached memory addresses, respectively.

## Dynamic Interrupt Slicing

To obtain a dynamic interrupt slice:

1. Use ioreplay and create a pandalog

``arm-softmmu/qemu-system-arm -machine rehosting,mem-map="MEM 0x00000000-0x3f000000"            `# Use rehosting machine with the appropriate mem-map to emulate` \ 
                            
                            -panda ioreplay:mem=raspi2.mem,cpu=raspi2.yaml,iovals=256         `# Use ioreplay with emulated machine's memory (.mem) and CPU (.yaml) snapshot, along with the fuzz value as iovals` \ 
                            
                            -panda llvm_trace2 -pandalog ioreplay.plog                        `# Use llvm_trace2, create pandalog` \ 
                            
                            -display none                                                     `# Disable QEMU display` ``

2. Create criteria for dynamic slicing

`echo 'TGT_R0 at rr:1-100' > criteria.txt`

3. Use dynslice2 with the pandalog and the criteria

`./dynslice2 arm llvm-mod.bc ioreplay.plog criteria.txt`

4. Using slice_analyzer, obtain the LLVM slice

`./slice_analyzer llvm-mod.bc slice_report.bin`
