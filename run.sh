#!/bin/bash

/home/nickgregory/auto-emulation2/arm-softmmu/qemu-system-arm -M rehosting -kernel /shared/kernel.elf -initrd /shared/rb-initrd -append "ubifs_support console=ttyS0,115200 lcd_ctrl=92 parts=1 boot_part_size=8388608 eth_mac=6C:3B:6B:1C:58:CE board=3011 ver=3.27 hw_opt=00518004 boot=1 mlc=10 debug" -panda "rehost:sym_file=/shared/rb-vmlinux.sym" -nographic
