
## build.sh diff
diff --git a/build.sh b/build.sh
index b47ecc6a56..94a42b8afd 100755
--- a/build.sh
+++ b/build.sh
@@ -41,7 +41,7 @@ fi
 
 
 export LD_LIBRARY_PATH=${PANDA_LLVM}/lib:$LD_LIBRARY_PATH
-CC=clang CXX=clang++ "$(dirname $0)/configure" \
+CC=clang-8 CXX=clang++-8 "$(dirname $0)/configure" \
     --disable-vhost-net \
     --disable-werror \
     --target-list=x86_64-softmmu,i386-softmmu,arm-softmmu,ppc-softmmu \



## build llvm 3.3 with clang 3.3
CC=clang-7 CXX=clang++-7 cmake -G Unix Makefiles -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=On -DCMAKE_INSTALL_PREFIX=/home/hu/llvm -DLLVM_REQUIRES_RTTI=ON  ..

## Make
CXXFLAGS=-I/usr/lib/llvm-7/include/c++/v1// LD_LIBRARY_PATH=/home/hu/llvm/lib/: make
