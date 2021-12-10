#!/bin/bash

PANDA_LLVM_ROOT="${PANDA_LLVM_ROOT:-$(realpath $(dirname $0)/../llvm)}"
set -e

if [ ! -d llvm-3.3.src ]; then
    curl https://releases.llvm.org/3.3/llvm-3.3.src.tar.gz -O && tar -xzf llvm-3.3.src.tar.gz
    curl https://releases.llvm.org/3.3/cfe-3.3.src.tar.gz -O && tar -xzf cfe-3.3.src.tar.gz && mv cfe-3.3.src llvm-3.3.src/tools/clang
    sed -i 's/check_include_file(sanitizer\/msan_interface.h HAVE_SANITIZER_MSAN_INTERFACE_H)//g' llvm-3.3.src/cmake/config-ix.cmake
fi

mkdir -p llvm-3.3.src/build
mkdir -p ${PANDA_LLVM_ROOT}
pushd llvm-3.3.src/build
CC=clang CXX=clang++ cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_REQUIRES_RTTI=ON -DBUILD_SHARED_LIBS=ON -DLLVM_USE_SANITIZER=OFF -DCMAKE_INSTALL_PREFIX=${PANDA_LLVM_ROOT} -G Ninja ..
ninja
ninja install
popd
