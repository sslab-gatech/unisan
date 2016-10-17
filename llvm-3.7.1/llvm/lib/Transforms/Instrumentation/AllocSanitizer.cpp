//===- AllocSanitizer.cpp - sanitize leaks caused by uninitialized read-----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/Casting.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Type.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Instrumentation.h"
#include <set>
#include <map>
#include <fstream>


using namespace llvm;

#define DL_NAME "allocsan"
#define DEBUG_TYPE DL_NAME

//#define DISABLE_SAFE_ALLOC 1
//#define INIT_ALL_ALLOC 1
//#define STACK_PROTECTION_ONLY 1
#define FULL_PROTECTION 1

#define RESULTS_FILE "/tmp/UnsafeAllocs.txt"


namespace {
	struct AllocSanitizer : public FunctionPass {
		static char ID; // Pass identification, replacement for typeid
		AllocSanitizer() : FunctionPass(ID) {
			initializeAllocSanitizerPass(*PassRegistry::getPassRegistry());
		}

		const TargetLibraryInfo *TLI;
		const DataLayout *DL;
		LLVMContext *Ctx;
		Type *IntPtrTy;
		Type *Int8Ty;
		Type *Int8PtrTy;
		Function *calloc;


		bool runOnFunction(Function &F) override {
			TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();

			initAllocations(F);

			return true;
		}

		void getAnalysisUsage(AnalysisUsage &AU) const override {
			AU.addRequired<TargetLibraryInfoWrapperPass>();
		}

		virtual bool doInitialization(Module &M);

		// initialize allocations
		bool initAllocations (Function &F);
		// check if it call kmalloc-like functions
		bool isKMallocCall(CallInst *CI);
		bool initStackAlloc(AllocaInst *AI);
		// add ZERO flag to kmalloc
		bool initHeapAlloc(CallInst *CI);

		void loadUnsafeAllocs(std::string mname);
	};
}

char AllocSanitizer::ID = 0;
static const char allocSanDesc[] = "Allocation Sanitizer Pass";
	INITIALIZE_PASS_BEGIN(AllocSanitizer, DL_NAME, allocSanDesc, false, false)
	INITIALIZE_PASS_DEPENDENCY(TargetLibraryInfoWrapperPass)
INITIALIZE_PASS_END(AllocSanitizer, DL_NAME, allocSanDesc, false, false)

	FunctionPass *llvm::createAllocSanitizerPass() {
		return new AllocSanitizer();
	}

// unsafe allocations that are already identified by our analysis
// pass
std::map<std::string, std::set<std::string>>FuncToUnsafeAllocs;

void AllocSanitizer::loadUnsafeAllocs(std::string mname) {
	std::ifstream file;
	file.open(RESULTS_FILE);
	std::string line, module, func, alloc;
	bool FoundModule = false;
	while (std::getline(file, line)) {
		if (line.find("module: ") == 0) {
			module = strdup(line.substr(8).c_str());
			if (module.size() <= mname.size() &&
					module == 
					mname.substr(mname.size() - module.size(), module.size())) {
				FoundModule = true;
			}
			else {
				if (FoundModule)
					break;
				FoundModule = false;
			}
		}
		else if (FoundModule) {
			if (line.find("\tfunction: ") == 0) {
				func = strdup(line.substr(11).c_str());
			}
			else if (line.find("\t\talloc: ") == 0) {
				alloc = strdup(line.substr(9).c_str());
				FuncToUnsafeAllocs[func].insert(alloc);
			}
		}
	}
}

bool AllocSanitizer::doInitialization(Module &M) {

	std::string module = M.getName().str();
	FuncToUnsafeAllocs.clear();
	loadUnsafeAllocs(module.substr(0, module.size() - 2));

	DL = &M.getDataLayout();
	Ctx = &M.getContext();
	IntPtrTy = DL->getIntPtrType(*Ctx);
	Int8Ty = Type::getInt8Ty(*Ctx);
	Int8PtrTy = Type::getInt8PtrTy(*Ctx);

	return true;
}

// initialize unsafe stack and heap allocations
bool AllocSanitizer::initAllocations (Function &F) {

#ifdef DISABLE_SAFE_ALLOC
	return false;
#endif

#ifndef INIT_ALL_ALLOC
	if (!FuncToUnsafeAllocs.count(F.getName().str()))
		return false;
#endif

	int Idx = 0;
	for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i) {
		++Idx;
		Instruction *I = &*i;
		// initialize variable allocations
		if (AllocaInst *AI = dyn_cast<AllocaInst>(I)) {
#ifndef INIT_ALL_ALLOC
			if (FuncToUnsafeAllocs[F.getName().str()]
					.count(AI->getName().str())) 
#endif
				initStackAlloc(AI);
		}
		// initialize malloced memory
		else if (CallInst *CI = dyn_cast<CallInst>(I)) {
#ifdef STACK_PROTECTION_ONLY
			continue;
#endif
			if (isKMallocCall(CI)) {
#ifndef INIT_ALL_ALLOC
				if (FuncToUnsafeAllocs[F.getName().str()]
						.count(std::to_string(Idx)))
#endif
					initHeapAlloc(CI);
			}
		}
	}
	return true;
}

// initialize stack allocas
bool AllocSanitizer::initStackAlloc(AllocaInst *AI) {

#ifdef DISABLE_SAFE_ALLOC
	return false;
#endif
	Type *AllocTy = AI->getAllocatedType();
	uint64_t TySize = DL->getTypeAllocSize(AllocTy);
	BasicBlock::iterator InsertPt = AI;
	++InsertPt;
	IRBuilder<> IRB(InsertPt);

	errs()<<"[AllocSanitizer] Initializing alloca "<<*AI<<"\n";
	//
	// static allocas
	//
	if (AI->isStaticAlloca()) {

		if (isa<ArrayType>(AllocTy) || isa<VectorType>(AllocTy)) {

			auto CArraySize = cast<ConstantInt>(AI->getArraySize());
			uint64_t Size = TySize * CArraySize->getZExtValue();
			if (!Size)
				return false;

			unsigned Align = AI->getAlignment();//DL->getABITypeAlignment(Ty);
			// define constant 0 of Int8Type
			Constant *C0 = Constant::getNullValue(Int8Ty);

			// call to llvm.memset
			IRB.CreateMemSet(
					AI,
					C0, Size, Align);
		}
		else {

			// define constant 0 of allocated type
			Constant *C0 = Constant::getNullValue(AI->getAllocatedType());

			// create storeinst to initialize the alloca
			IRB.CreateStore(C0, AI);
		}
	}
	//
	// dynamic allocas
	// 
	else {

		// size has to be computed dynamically
		Value *ArraySize = AI->getArraySize();
		// cast type of ArraySize to IntPtrTy
		if (ArraySize->getType() != IntPtrTy)
			ArraySize = 
				IRB.CreateIntCast(ArraySize, IntPtrTy, false);
		Value *Size = 
			IRB.CreateMul(ArraySize, ConstantInt::get(IntPtrTy, TySize));

		unsigned Align = AI->getAlignment();
		// define constant 0 of Int8Type
		Constant *C0 = Constant::getNullValue(Int8Ty);

		// call to llvm.memset
		IRB.CreateMemSet(AI, C0, Size, Align);
	}

	return true;
}
std::set<std::string> KMallocFuncs = {
	"kmalloc",
	"__kmalloc",
	//"kmem_cache_alloc",
	"__alloc_skb",
};

// if it is a kernel malloc without initialization
bool AllocSanitizer::isKMallocCall(CallInst *CI) {

	Function *F = CI->getCalledFunction();
	if (!F)
		return false;

	StringRef FName = F->getName();
	if (!KMallocFuncs.count(FName.str()))
		return false;

	if (CI->getNumArgOperands() < 2)
		return false;

	return true;
}

// initialize the unsafe heap allocation
bool AllocSanitizer::initHeapAlloc(CallInst *CI) {
	Value *FlagArg = CI->getArgOperand(1);
	ConstantInt *CFlagArg = dyn_cast<ConstantInt>(FlagArg);
	if (!CFlagArg)
		return false;

	// has initialization already (i.e., with __GFP_ZERO)
	if (CFlagArg->getZExtValue() & 0x8000u)
		return false;

	errs()<<"[AllocSanitizer] Initializing kmalloc "<<*CI<<"\n";
	// construct the new flag arg with __GFP_ZERO
	ConstantInt *NewFlags = ConstantInt::get(
			*Ctx, 
			APInt(32, CFlagArg->getZExtValue() | 0x8000u, true));

	CI->setArgOperand(1, NewFlags);

	return true;
}


