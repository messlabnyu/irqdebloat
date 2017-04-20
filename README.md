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
