CUR_DIR = $(realpath $(LEVEL))
LLVM_BIN := $(CUR_DIR)/../../llvm-3.7.1/build/bin
LLVM_LIB := $(CUR_DIR)/../../llvm-3.7.1/build/lib

BCS=$(SRCS:.c=.bc)

BUILD_FLAG = -pie -fPIC -g -O0 -fsanitize=alloc -Wuninitialized 

all: test.bin merged.bc

$(BCS): $(SRCS)
	$(LLVM_BIN)/clang $(BUILD_FLAG) -emit-llvm -c $^ 

merged.bc: $(BCS)
	$(LLVM_BIN)/llvm-link $^ -o $@ 

#merged_opt.bc: merged.bc
#	$(LLVM_BIN)/opt -load $(LLVM_LIB)/LLVMLeakSan.so -leaksan < merged.bc > $@ 
	$(LLVM_BIN)/llvm-dis $@ 

test.bin: merged.bc
	PATH=$(LLVM_BIN):$(PATH) $(LLVM_BIN)/clang $(BUILD_FLAG) $^ -o $@


run:
	./test.bin

clean:
	@rm -rf *.bin *.bc *.ll

.PHONY: all run clean test
