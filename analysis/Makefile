CUR_DIR = $(shell pwd)
LLVM_SRC := ${CUR_DIR}/../llvm-3.7.1/llvm
LLVM_BUILD := ${CUR_DIR}/../llvm-3.7.1/prefix
UNISAN_DIR := ${CURDIR}/src
UNISAN_BUILD := ${CURDIR}/build

NPROC := ${shell nproc}

build_unisan_func = \
	(mkdir -p ${2} \
		&& cd ${2} \
		&& PATH=${LLVM_BUILD}/bin:${PATH} \
			LLVM_ROOT_DIR=${LLVM_BUILD}/bin \
			LLVM_LIBRARY_DIRS=${LLVM_BUILD}/lib \
			LLVM_INCLUDE_DIRS=${LLVM_BUILD}/include \
			CC=clang CXX=clang++ \
            cmake ${1} -DCMAKE_BUILD_TYPE=Release \
                -DCMAKE_CXX_FLAGS_RELEASE="-std=c++11 -fno-rtti -fpic" \
		&& make -j${NPROC})

all: unisan

unisan:
	$(call build_unisan_func, ${UNISAN_DIR}, ${UNISAN_BUILD})
