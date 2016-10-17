#ifndef _UNISAN_GLOBAL_H
#define _UNISAN_GLOBAL_H

#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instructions.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringExtras.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>
#include "llvm/Support/CommandLine.h"
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "Common.h"
#include "SAStructs.h"


// 
// typedefs
//
typedef std::vector< std::pair<llvm::Module*, llvm::StringRef> > ModuleList;
// Mapping module to its file name.
typedef std::unordered_map<llvm::Module*, llvm::StringRef> ModuleNameMap;
// The set of all functions.
typedef llvm::SmallPtrSet<llvm::Function*, 8> FuncSet;
// Mapping from function name to function.
typedef std::unordered_map<std::string, llvm::Function*> NameFuncMap;
typedef llvm::SmallPtrSet<llvm::CallInst*, 8> CallInstSet;
typedef llvm::DenseMap<llvm::Function*, CallInstSet> CallerMap;
typedef llvm::DenseMap<llvm::CallInst *, FuncSet> CalleeMap;


struct GlobalContext {

  GlobalContext() {
		// Initialize statistucs.
    NumStaticAllocas = 0;
    NumDynamicAllocas = 0;
    NumUnsafeAllocas = 0;
    NumStaticMallocs = 0;
    NumDynamicMallocs = 0;
    NumUnsafeMallocs = 0;
    NumFunctions = 0;
		NumAllocaBytes = 0;
		NumUnsafeAllocaBytes = 0;
		NumMallocBytes = 0;
		NumUnsafeMallocBytes = 0;
  }

  // Statistics for allocations.
  unsigned NumStaticAllocas;
  unsigned NumDynamicAllocas;
  unsigned NumAllocaBytes;
  unsigned NumUnsafeAllocaBytes;
  unsigned NumUnsafeAllocas;
  unsigned NumStaticMallocs;
  unsigned NumDynamicMallocs;
  unsigned NumUnsafeMallocs;
  unsigned NumMallocBytes;
  unsigned NumUnsafeMallocBytes;
  unsigned NumFunctions;
  std::set<Value *> ValueCounter;

	// Map global function name to function defination.
	NameFuncMap Funcs;

  // Functions whose addresses are taken.
  FuncSet AddressTakenFuncs;

	// Map a callsite to all potential callee functions.
	CalleeMap Callees;

	// Map a function to all potential caller instructions.
	CallerMap Callers;

  // Indirect call instructions.
  std::vector<CallInst *>IndirectCallInsts;

	// Modules.
  ModuleList Modules;
  ModuleNameMap ModuleMaps;
  std::set<std::string> InvolvedModules;

  // The store target is safe if it is local.
  DenseMap<Function*, SmallPtrSet<Value *, 8>>SafeStoreTargets;
  DenseMap<Function*, SmallPtrSet<Value *, 8>>UnsafeStoreTargets;

  // The signatures of functions that may leak kernel data to user 
	// space, stored in file sink.sig.
  std::unordered_map<std::string, std::set<int>> SinkFuncs;
  // Some manaully-verified functions that will not reach sink 
	// functions.
  std::set<std::string> NonSinkFuncs;
  // Some manually-summarized functions that initialize
  // values.
  std::map<std::string, std::pair<uint8_t, int8_t>> InitFuncs;
  std::map<std::string, std::tuple<uint8_t, uint8_t, int8_t>> CopyFuncs;
  std::set<std::string> HeapAllocFuncs;
};

class IterativeModulePass {
protected:
	GlobalContext *Ctx;
	const char * ID;
public:
	IterativeModulePass(GlobalContext *Ctx_, const char *ID_)
		: Ctx(Ctx_), ID(ID_) { }

	// Run on each module before iterative pass.
	virtual bool doInitialization(llvm::Module *M)
		{ return true; }

	// Run on each module after iterative pass.
	virtual bool doFinalization(llvm::Module *M)
		{ return true; }

	// Iterative pass.
	virtual bool doModulePass(llvm::Module *M)
		{ return false; }

	virtual void run(ModuleList &modules);
};

#endif
