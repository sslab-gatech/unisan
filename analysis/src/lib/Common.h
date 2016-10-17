#ifndef UNISAN_COMMON_H
#define UNISAN_COMMON_H

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/CommandLine.h>

#include <unistd.h>
#include <bitset>
#include <chrono>

using namespace llvm;

#define LOG(lv, stmt)							\
	do {											\
		if (VerboseLevel >= lv)						\
		errs() << stmt;							\
	} while(0)


#define OP llvm::errs()

#define WARN(stmt) LOG(1, "\n[WARN] " << stmt);

#define ERR(stmt)													\
	do {																\
		errs() << "ERROR (" << __FUNCTION__ << "@" << __LINE__ << ")";	\
		errs() << ": " << stmt;											\
		exit(-1);														\
	} while(0)


extern cl::opt<unsigned> VerboseLevel;


#endif
