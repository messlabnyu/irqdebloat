# Automated Rehosting

## Setup

0. Clone
1. `cd panda/plugins/rehost; protoc --proto_path=. --cpp_out=. packets.proto; cd ../../../`
2. `./panda/scripts/install_ubuntu.sh`


## Theory/overview

Theory docs with overview of algorithms used and more are [here](./THEORY.md).


<<<<<<< HEAD
## TODO
=======
```
sudo add-apt-repository ppa:phulin/panda
sudo apt-get update
sudo apt-get build-dep qemu
sudo apt-get install python-pip git protobuf-compiler protobuf-c-compiler \
  libprotobuf-c0-dev libprotoc-dev python-protobuf libelf-dev \
  libcapstone-dev libdwarf-dev python-pycparser llvm-3.3 clang-3.3 libc++-dev
git clone https://github.com/panda-re/panda
mkdir -p build-panda && cd build-panda
../panda/build.sh
```
>>>>>>> 9adf4a1d79475b091045d91be510e258e6a2c476

* Incorporate building packets.proto into the install script
* Automatically extract everything we need from any input format (e.g. given an ELF, extract vmlinux and initrd; given a vmlinuz and initrd, extract vmlinux, and create an ELF for QEMU)
