// SPDX-License-Identifier: MIT
//===-- UniSan.cc - the UniSan framework------------------------===//
// 
// This file implemets the UniSan framework. It calls the pass for
// building call-graph and the pass for finding unsafe allocations.
// It outputs the information of unsafe allocations for further
// instrumentation (i.e., zero-initialization). The iterative 
// analysis strategy is borrowed from KINT[OSDI'12] to avoid 
// combining all bitcode files into a single one. 
//
//===-----------------------------------------------------------===//

#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/SystemUtils.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/Path.h"

#include <memory>
#include <vector>
#include <sstream>
#include <sys/resource.h>

#include "UniSan.h"
#include "CallGraph.h"
#include "SafeAllocation.h"
#include "Config.h"


using namespace llvm;

// Command line parameters.
cl::list<std::string> InputFilenames(
    cl::Positional, cl::OneOrMore, cl::desc("<input bitcode files>"));

cl::opt<unsigned> VerboseLevel(
    "verbose-level", cl::desc("Print information at which verbose level"),
    cl::init(0));

cl::opt<bool> SafeAlloc(
    "safe-alloc", 
    cl::desc("Initialize allocations that are subject to uninitialized leaks"), 
    cl::NotHidden, cl::init(false));

GlobalContext GlobalCtx;


void IterativeModulePass::run(ModuleList &modules) {

  ModuleList::iterator i, e;
  OP << "[" << ID << "] Initializing " << modules.size() << " modules ";
  bool again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      again |= doInitialization(i->first);
      OP << ".";
    }
  }
  OP << "\n";

  unsigned iter = 0, changed = 1;
  while (changed) {
    ++iter;
    changed = 0;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      OP << "[" << ID << " / " << iter << "] ";
      OP << "[" << i->second << "]\n";

      bool ret = doModulePass(i->first);
      if (ret) {
        ++changed;
        OP << "\t [CHANGED]\n";
      } else
        OP << "\n";
    }
    OP << "[" << ID << "] Updated in " << changed << " modules.\n";
  }

  OP << "[" << ID << "] Postprocessing ...\n";
  again = true;
  while (again) {
    again = false;
    for (i = modules.begin(), e = modules.end(); i != e; ++i) {
      // TODO: Dump the results.
      again |= doFinalization(i->first);
    }
  }

  OP << "[" << ID << "] Done!\n\n";
}

void LoadStaticData(GlobalContext *GCtx) {

  // load sink functions
	SetSinkFuncs(GCtx->SinkFuncs);
  // load non-sink functions
	SetNonSinkFuncs(GCtx->NonSinkFuncs);
	// load functions that initialize/overwrite values
	SetInitFuncs(GCtx->InitFuncs);
	// load functions that copy/move values
	SetCopyFuncs(GCtx->CopyFuncs);
	// load functions for heap allocations
	SetHeapAllocFuncs(GCtx->HeapAllocFuncs);
}

int main(int argc, char **argv)
{

  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal();
  PrettyStackTraceProgram X(argc, argv);

  llvm_shutdown_obj Y;  // Call llvm_shutdown() on exit.

  cl::ParseCommandLineOptions(argc, argv, "global analysis\n");
  SMDiagnostic Err;

  // Loading modules
  OP << "Total " << InputFilenames.size() << " file(s)\n";

  for (unsigned i = 0; i < InputFilenames.size(); ++i) {

    LLVMContext *LLVMCtx = new LLVMContext();
    std::unique_ptr<Module> M = parseIRFile(InputFilenames[i], Err, *LLVMCtx);

    if (M == NULL) {
      OP << argv[0] << ": error loading file '"
        << InputFilenames[i] << "'\n";
      continue;
    }

    Module *Module = M.release();
		StringRef MName = StringRef(strdup(InputFilenames[i].data()));
    GlobalCtx.Modules.push_back(std::make_pair(Module, MName));
    GlobalCtx.ModuleMaps[Module] = InputFilenames[i];
  }

  // Main workflow
	// Build global callgraph.
  CallGraphPass CGPass(&GlobalCtx);
  CGPass.run(GlobalCtx.Modules);

	// The safe allocation pass of UniSan.
  if (SafeAlloc) {
    // Clear the results.
    fopen(RESULTS_FILE, "w"); 
    LoadStaticData(&GlobalCtx);

    SafeAllocation SAPass(&GlobalCtx);
    SAPass.run(GlobalCtx.Modules);

		// Print results
    SAPass.PrintStatistics();
  }

  return 0;
}

