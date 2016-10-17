#ifndef _SAFE_ALLOCATION_H
#define _SAFE_ALLOCATION_H

#include "UniSan.h"
#include "SAStructs.h"

class SafeAllocation : public IterativeModulePass {

	private:
		const DataLayout* DL;
		// long integer type
		Type *IntPtrTy;
		// type for universal pointer, e.g., char * and void *
		Type *Int8Ty;

		// Record unsafe allocations
		std::map<StringRef, std::set<StringRef>>UnsafeAllocs;


		bool runOnFunction(llvm::Function *);
		// Sanity-check stack allocations
		bool SanitizeAlloca(AllocaInst *);
		// Sanity-check heap allocations
		bool SanitizeMalloc(CallInst *);
		// Track a value
		bool TrackValue(Value *, AllocState *, Element *Ele,
				Value *StartUser);
		// Track a user of the tracked value (or its alias)
		bool TrackUser(UserNode *, AllocState *, UserGraph *UG);
		// Track next users 
		bool TrackNextUsers(UserNode *, AllocState *, UserGraph *UG);
		// Track the resulted value and next user in parallel for
		// Load and store instructions
		bool TrackInParallel(Value *, UserNode *, 
				AllocState *, UserGraph *UG);
		// Track the argument if the tracked value is passed to
		// functions
		bool TrackArg(UserNode *, unsigned ArgNo, 
				AllocState *, UserGraph *UG);
		// Track an alias (store-to value in a store instruction)
		bool TrackAliasSet(UserNode *, AllocState *, 
				std::set<SafeAliasSet *> *AliasSets, UserGraph *UG);
		// Track in a set of values; the most unsafe one is chosen
		bool TrackValueSet(std::set<Value *> *ValueSet, 
				AllocState *AS, Element *Ele);
		// Initialized the allocation if it is not safe
		bool InitStaticAlloc(Instruction *, AllocState *);
		bool InitDynamicAlloc(Instruction *);

		// Find safe alias sets. If it cannot find all aliases or any
		// alias is passed to non-stack memory, it returns false, and we
		// assume the tracked value is sunk.
		bool FindSafeAliasSets(SafeAlias *SA, 
				std::set<SafeAliasSet *> *AliasSets,
				SmallPtrSet<Value*, 8> *Visited,
				SafeAliasSet *AliasSet = NULL);

		// Utils
		Argument *GetArgByArgNo(Function *, unsigned);
		int GetInsIdxInFunction(Instruction *I);
		void WriteUnsafeAllocs(Module *M);

	public:
		SafeAllocation(GlobalContext *Ctx_)
			: IterativeModulePass(Ctx_, "SafeAlloc") { 
			}

		void PrintStatistics();

		virtual bool doModulePass(llvm::Module *);
		virtual bool doInitialization(llvm::Module *);
		virtual bool doFinalization(llvm::Module *);
};

#endif
