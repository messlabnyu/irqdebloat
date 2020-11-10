targets rpi3.a53.3
halt
targets rpi3.a53.2
halt
targets rpi3.a53.1
halt
targets rpi3.a53.0
halt
#mdb phys 0 1073741824
#dump_image raspi2_mem.log 0 1073741824
dump_image raspi2_mem.log 0 0x40000000
