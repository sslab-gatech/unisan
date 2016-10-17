#!/bin/bash -e

ROOT=$(git rev-parse --show-toplevel)
cd $ROOT/llvm-3.7.1

if [ ! -d "build" ]; then
  mkdir build
fi

cd build
cmake -DLLVM_TARGET_ARCH="ARM;X86;AArch64" -DLLVM_TARGETS_TO_BUILD="ARM;X86;AArch64" -DCMAKE_BUILD_TYPE=Release ../llvm
make -j8

if [ ! -d "$ROOT/llvm-3.7.1/prefix" ]; then
  mkdir $ROOT/llvm-3.7.1/prefix
fi

cmake -DCMAKE_INSTALL_PREFIX=$ROOT/llvm-3.7.1/prefix -P cmake_install.cmake
