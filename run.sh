#!/bin/bash

timeout --foreground 30s /home/nickgregory/auto-emulation2-runner/arm-softmmu/qemu-system-arm -M rehosting -kernel /shared/kernel.elf -initrd /shared/rb-initrd -append "ubifs_support console=ttyS0,115200 lcd_ctrl=92 parts=1 boot_part_size=8388608 eth_mac=6C:3B:6B:1C:58:CE board=3011 ver=3.27 hw_opt=00518004 boot=1 mlc=10 debug" -machine board-id=4200 -machine "mem-map=MEM 0x40000000-0x80000000" -panda "rehost:server=127.0.0.1 12345,id=0" -nographic
