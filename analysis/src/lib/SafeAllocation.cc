//===-- SafeAllocation.cc - Finding unsafe allocations ---------===//
// 
// This pass conservatively identifies unsafe allocation that are 
// subject to uninitialized data leaks. It emploies data-flow
// analysis to keep track of each byte of an allocation (including
// both stack and heap allocations)---if any byte cannot be proven to
// be initialized in all possible paths when it reaches sink
// functions (e.g., copy_to_user), we say this allocation is unsafe.
//
//===-----------------------------------------------------------===//

#include "llvm/Pass.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/TypeFinder.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CallSite.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringMap.h"
#include <set>
#include <map>
#include <queue>
#include <vector>
#include <list>
#include <sys/types.h>
#include <unistd.h>
#include <iostream>
#include <fstream>

#include "Common.h"

#include "SafeAllocation.h"
#include "Config.h"

using namespace llvm;



//
// Implementation of the SafeAllocation pass.
//
// Sanity-check the stack allocation to see if it may reach sink 
// functions without being fully initialized.
bool SafeAllocation::SanitizeAlloca(AllocaInst *AI) {

	AllocState AS(AI, DL);
	// The original element is the allocated object.
	Element Ele(AI, DL);

	if (AI->isStaticAlloca()) {

		++Ctx->NumStaticAllocas;
		Ctx->NumAllocaBytes += AS.size;

#ifdef VERBOSE_SA
		OP<<"[Alloca] "<<*AI<<" - "
			<<AI->getParent()->getParent()->getName()<<"\n";
#endif

		// Start tracking
		TrackValue(AI, &AS, &Ele, AI);

		// Initialize it if it may reach sink functions without being 
		// fully initialized.
		if (!AS.AllBytesSafe(0, AS.size))
			// Initialized the allocation.
			InitStaticAlloc(AI, &AS);
	}
	else {
		++Ctx->NumDynamicAllocas;

#ifdef VERBOSE_SA
		OP<<"[Alloca] "<<*AI<<" - "
			<<AI->getParent()->getParent()->getName()<<"\n";
#endif

		// Track initialization.
		TrackValue(AI, &AS, &Ele, AI);

		// For dynamic allocation, we conservatively assume it is not 
		// initialized and only care about if it reaches sink functions.
		if (AS.reachSink)
			InitDynamicAlloc(AI);
	}

	AS.Release();

	return false;
}

// Sanity-check the heap allocation to see if it may reach sink 
// functions without being fully initialized.
bool SafeAllocation::SanitizeMalloc(CallInst *CI) {

	Value *SizeArg = CI->getArgOperand(0);
	ConstantInt *CSizeArg = dyn_cast<ConstantInt>(SizeArg);
	// If size is constant.
	if (CSizeArg) {
		++Ctx->NumStaticMallocs;
		Ctx->NumMallocBytes += CSizeArg->getZExtValue();
	}
	else
		++Ctx->NumDynamicMallocs;

	Value *FlagArg = CI->getArgOperand(1);
	if (ConstantInt *CFlagArg = 
			dyn_cast<ConstantInt>(FlagArg)) {  
		// If ___GFP_ZERO is used, the heap allocation is already 
		// initialized. In this case, it is safe, so we skip it.
		//  #define ___GFP_ZERO   0x8000u
		if (CFlagArg->getZExtValue() & 0x8000u)
			return false;
	}
	else
		return false;

	AllocState AS(CI, DL);
	Element Ele(CI, DL);

	if (CSizeArg) {

#ifdef VERBOSE_SA
		OP<<"[Malloc] "<<*CI<<" - "
			<<CI->getParent()->getParent()->getName()<<"\n";
#endif

		// Track static heap allocation.
		TrackValue(CI, &AS, &Ele, CI);

		// Initialize it if not all of its bytes are safe.
		if (!AS.AllBytesSafe(0, AS.size))
			InitStaticAlloc(CI, &AS);
	}
	else {

#ifdef VERBOSE_SA
		OP<<"[Malloc] "<<*CI<<" - "
			<<CI->getParent()->getParent()->getName()<<"\n";
#endif

		// Track dynamic heap allocation.
		TrackValue(CI, &AS, &Ele, CI);

		if (AS.reachSink)
			InitDynamicAlloc(CI);
	}

	AS.Release();
	return false;
}

// Initialize the static allocation (i.e., size is known).
bool SafeAllocation::InitStaticAlloc(Instruction *I,
		AllocState *AS) {

#ifdef VERBOSE_SA
	OP<<"[Unsafe static alloc] "<<*I<<" - "
		<<F->getName()<<" - size="<<AS->size<<"\n";
#endif

	if (isa<AllocaInst>(I)) {
		++Ctx->NumUnsafeAllocas;
		Ctx->NumUnsafeAllocaBytes += AS->NumUnsafeBytes();
	}
	else if (isa<CallInst>(I)) {
		++Ctx->NumUnsafeMallocs;
		Ctx->NumUnsafeMallocBytes += AS->NumUnsafeBytes();
	}

	Function *F = I->getParent()->getParent();
	if (isa<AllocaInst>(I)) {
		if (I->hasName())
			UnsafeAllocs[F->getName()].insert(I->getName());
	}
	else {
		int Idx = GetInsIdxInFunction(I);
		assert(Idx > 0);
		char *IdxStr =  strdup(std::to_string(Idx).c_str());
		UnsafeAllocs[F->getName()].insert(StringRef(IdxStr));
	}

	// FIXME: instrumentation part is implemented seperately.

	return false;
}

// Initialize the dynamic allocation.
bool SafeAllocation::InitDynamicAlloc(Instruction *I) {

#ifdef VERBOSE_SA
	OP<<"[Unsafe dynamic alloc] "<<*I<<" - "
		<<I->getParent()->getParent()->getName()<<"\n";
#endif

	if (isa<AllocaInst>(I))
		++Ctx->NumUnsafeAllocas;
	else if (isa<CallInst>(I)) {
		++Ctx->NumUnsafeMallocs;
	}

	Function *F = I->getParent()->getParent();
	if (isa<AllocaInst>(I)) {
		if (I->hasName())
			UnsafeAllocs[F->getName()].insert(I->getName());
	}
	else {
		int Idx = GetInsIdxInFunction(I);
		assert(Idx >= 0);
		if (Idx >= 0) {
			char *IdxStr =	strdup(std::to_string(Idx).c_str());
			UnsafeAllocs[F->getName()].insert(StringRef(IdxStr));
		}
	}

	// FIXME: instrumentation part is implemented seperately.
	return false;
}

// 
// Function: track value;
// V: to be tracked value;
// StartUser: the tracking starts from StartUser.
//
bool SafeAllocation::TrackValue(Value *V, AllocState *AS, 
		Element *Ele, Value *StartUser) {

	if (V->use_empty())
		return false;

	// Build its user graph.
	UserGraph UG(V, StartUser, Ele);
#ifdef VERBOSE_SA
	UG.PrintGraph(V);
#endif

	// Track the users of the value.
	TrackNextUsers(UG.FirstUN, AS, &UG);

	return false;
}

// 
// Function: track next users of current user;
// UN: current user node.
//
bool SafeAllocation::TrackNextUsers(
		UserNode *UN, 
		AllocState * AS, 
		UserGraph *UG) {

	bool Changed = false;
	unsigned NumNextUsers  = UN->nextUserNodes.size();
	if (NumNextUsers == 0)
		return false;

	// Stop if all bytes are already initialized or sunk.
	if (AS->AllBytesInited() || AS->AllBytesSunk())
		return Changed;

	// Only one next user; no need to merge.
	if (NumNextUsers == 1) {
		Changed |= TrackUser(
				*(UN->nextUserNodes.begin()), AS, UG);

		return Changed;
	}

	// If there are multiple next users, tracking results of each 
	// next user should be conservatively merged.
	unsigned Count = 0;
	AllocState ASMerge(AS);
	// Cache the next user nodes, since they may be updated.
	std::set<UserNode *>NextUsers = UN->nextUserNodes;
	std::set<Element *>FullyInitedEles = AS->fullyInitedEles;
	std::set<Element *>FullySunkEles = AS->fullySunkEles;
	for (UserNode *Next : NextUsers) {

		Count ++;

		if (Count == 1) {
			Changed |= TrackUser(Next, &ASMerge, UG);
		}
		else {
			AllocState ASFork(AS);
			Changed |= TrackUser(Next, &ASFork, UG);
			// Merge allocation states.
			ASMerge.Merge(&ASFork);
		}
		// Restore
		AS->fullyInitedEles = FullyInitedEles;
		AS->fullySunkEles = FullySunkEles;

		// If all bytes are unsafe, no need to further track.
		if (ASMerge.AllBytesUnsafe(0, AS->size)) {
			AS->FastCopy(&ASMerge);
			return Changed;
		}
	}
	// Use the final merged state.
	AS->FastCopy(&ASMerge);

	return Changed;
}

// 
// Function: track a user of the value;
// V: being tracked value.
//
bool SafeAllocation::TrackUser(
		UserNode *UN, 
		AllocState * AS, 
		UserGraph *UG) {

	User *U = dyn_cast<User>(UN->U);
	assert (U);

#ifdef DEBUG_SA
	OP<<"[User] "<<*U<<" - "
		<<(dyn_cast<Instruction>(U))->getParent()->getParent()->getName()
		<<" - refHierarchy="<<UN->ele->refHierarchy<<"\n";
#endif

	// Check if it is already tracked.
	if (AS->trackedUsers->count(U)) {
		if (AS->isDynamic)
			return false;
		for (uint8_t *Flags : AS->trackedUsers->find(U)->second) {
			// If exactly same case (same flags) has be tracked already,
			// stop the tracking.
			if (memcmp(Flags, AS->bytesFlags, AS->size) == 0) {
				return false;
			}
		}
	}
	else {
		AS->trackedUsers->insert(
				std::pair<User *, std::set<uint8_t *>>(
					U, std::set<uint8_t *>()));
	}

	// Assume it is sunk if it takes too much time.
	if (AS->trackedUsers->find(U)->second.size() > 100 ||
			AS->trackedUsers->size() > 10000) {
		AS->SetSinkFlag(UN->ele->offset, UN->ele->size);
		AS->AddFullySunkEle(UN->ele);
		return false;
	}
	// Cache 
	if (!AS->isDynamic) {
		uint8_t *Flags = (uint8_t *)malloc(AS->size);
		memcpy(Flags, AS->bytesFlags, AS->size);
		AS->trackedUsers->find(U)->second.insert(Flags);
	}
	// Skip the tracking of the user if whole element is already 
	// initialized or sunk.
	if (
			AS->IsFullyInitedEle(UN->ele) ||
			AS->IsFullySunkEle(UN->ele) ||
			AS->IsElementInited(UN->ele) ||
			AS->IsElementSunk(UN->ele)
		 ) {
		return TrackNextUsers(UN, AS, UG);
	}

	//
	// Now, do the actual user tracking.
	//
	bool Changed = false;

	// Handle LoadInst
	if (LoadInst *LI = dyn_cast<LoadInst>(U)) {

		if (UN->ele->refHierarchy >= 0)
			// Tracking the loaded value pointed to by the being tracked 
			// value is out of scope.
			return TrackNextUsers(UN, AS, UG);

		// Track the loaded value and next user in parallel.
		Changed |= TrackInParallel(LI, UN, AS, UG);

		return Changed;
	}
	// Handle StoreInst.
	else if (StoreInst *SI = dyn_cast<StoreInst>(U)) {

		Value *VOpe = SI->getValueOperand();
		Value *POpe = SI->getPointerOperand();
		// The tracked value is used as the value operand, i.e., it 
		// propagates to other values.
		if (UG->usedValues.count(VOpe)) {

			assert (UN->ele->refHierarchy <= 0);

			// Use the conservative basic alias analysis to find the 
			// aliases of the tracked value.
			// If it may propagate to non-stack memory, we assume it is 
			// unsafe (i.e., return false in FindSafeAliasSets)
			SafeAlias SA(POpe, 0);
			std::set<SafeAliasSet *> AliasSets;
			SmallPtrSet<Value*, 8> Visited;
#ifdef SOUND_MODE
			if (!FindSafeAliasSets(&SA, &AliasSets, &Visited))
#else
			FindSafeAliasSets(&SA, &AliasSets, &Visited);
			if (!AliasSets.size()) 
#endif
			{
				// Conservatively assume it is sunk.
				AS->SetSinkFlag(UN->ele->offset, UN->ele->size);
				AS->AddFullySunkEle(UN->ele);

				return TrackNextUsers(UN, AS, UG);
			}
			else {
				// Now, track each alias and merge results.
				AllocState AliasAS(AS);
				Changed |= TrackAliasSet(UN, &AliasAS, &AliasSets, UG);
				if (UN->nextUserNodes.size()) {
					Changed |= TrackNextUsers(UN, AS, UG);
					AS->Merge(&AliasAS);
				}
				else
					AS->FastCopy(&AliasAS);
			}

			ReleaseAliasSets(&AliasSets);
			return Changed;
		}
		// The tracked value is used as the pointer operand, 
		// i.e., assigned by other values.
		else {
			if (UN->ele->refHierarchy == -1) {
				Changed = true;
				// Get the size (in bytes) of the store operation.
				uint64_t Size = 
					DL->getTypeAllocSize(VOpe->getType());
				if (!UN->ele->unknownOffset) {
					// XXX: overwritting might be a spacial memory error.
					if (UN->ele->offset + Size > AS->size)
						Size = AS->size - UN->ele->offset;

					// Bookkeeping of the initialization.
					AS->SetInitFlag(UN->ele->offset, Size);
				}
				// Check if the element is already completely initialized.
				if (UN->ele->size && Size >= UN->ele->size)
					AS->AddFullyInitedEle(UN->ele);
			}

			Changed |= TrackNextUsers(UN, AS, UG);
			return Changed;
		}
	}
	// Handle call instruction.
	else if (CallInst *CI = dyn_cast<CallInst>(U)) {

		// XXX: dereferencing an uninitialized value could result in an 
		// undefined behavior.
		if (CI->getCalledValue() == U)
			return TrackNextUsers(UN, AS, UG);

		// Handle inline assembly conservatively.
		if (CI->isInlineAsm()) {
			if (InlineAsm *Asm = 
					dyn_cast<InlineAsm>(CI->getCalledValue())) {
				std::string AsmStr = Asm->getAsmString();
				// Assume it is safe, if the asm does not have any call or jmp;
				// otherwise, assume it is unsafe.
				if (AsmStr.find("call") == std::string::npos &&
						AsmStr.find("jmp") == std::string::npos &&
						AsmStr.find("mov") == std::string::npos
					 )
					return TrackNextUsers(UN, AS, UG);
			}

			// In any other cases, the inline assembly is conservatively
			// assumed as a sink.
			AS->SetSinkFlag(UN->ele->offset, UN->ele->size);
			AS->AddFullySunkEle(UN->ele);

			return TrackNextUsers(UN, AS, UG);
		}

		// The tracked value is used as an argument.
		CallSite CS(CI);
		unsigned ArgNo = 0;
		for (CallSite::arg_iterator ai = CS.arg_begin(), 
				ae = CS.arg_end();
				ai != ae; ++ai) {
			if (UG->usedValues.count(*ai)) {
				// further track the arg
				Changed |= TrackArg(UN, ArgNo, AS, UG);
			}
			else
				++ArgNo;
		}

		return TrackNextUsers(UN, AS, UG);
	}
	// Handle return instruction.
	else if (ReturnInst *RI = dyn_cast<ReturnInst>(U)) {

		// Get callers of current function.
		Function *F = RI->getParent()->getParent();

		std::set<Value *> ValueSet;
		for (Value *V : Ctx->Callers[F])
			ValueSet.insert(V);
		Changed |= TrackValueSet(&ValueSet, AS, UN->ele);

		Changed |= TrackNextUsers(UN, AS, UG);

		return Changed;
	}
	// Handle GEP
	// This is the important part for implementing byte-level analysis.
	// We try to keep track of the offset of the pointer into the base
	// of the allocation. Of course, if the indice is not constant, we
	// cannot know the offset; in this case, we stop initialization
	// analysis and continue with only reachability analysis.
	else if (GEPOperator *GO = 
			dyn_cast<GEPOperator> (U)) {

		// FIXME: verify soundness
		if (UN->ele->refHierarchy != -1)
			return TrackNextUsers(UN, AS, UG);

		Element *NewEle = new Element(UN->ele);
		NewEle->UpdateByGEP(GO, DL);

		if (NewEle->offset >= AS->size && !AS->isDynamic) {
			delete NewEle;
			return TrackNextUsers(UN, AS, UG);
		}

		NewEle->parentEle = UN->ele;
		AS->Eles.insert(NewEle);
		// XXX: this is could be a spacial memory error, 
		// if (element.offset + element.size) > size.
		// Since we target only uninitialized read, skip this problem.
		if (NewEle->offset + NewEle->size > AS->size &&
				!AS->isDynamic)
			NewEle->size = AS->size - NewEle->offset;

		UG->MergeUsers(U, NewEle, U);
		UG->usedValues.insert(U);

		Changed |= TrackNextUsers(UN, AS, UG);

		return Changed;
	}
	// Handle casting.
	else if (CastInst *Cast = dyn_cast<CastInst>(U)) {

		if (!AS->isDynamic && 
				(isa<SExtInst>(Cast) ||
				 isa<ZExtInst>(Cast))) {
			unsigned NewSize = DL->getTypeAllocSize(Cast->getType());
			if (NewSize > AS->size) {
				AS->bytesFlags = (uint8_t *)realloc(AS->bytesFlags, NewSize);
				memset(AS->bytesFlags + AS->size, 
						!ByteInited|!ByteSunk|!ByteUnsafe, 
						NewSize - AS->size);
				AS->size = NewSize;
			}
		}

		UG->MergeUsers(U, UN->ele, U);
		// Track the next users.
		UG->usedValues.insert(Cast);
		Changed |= TrackNextUsers(UN, AS, UG);

		return Changed;
	}
	// Recursively track the following instructions.
	else if (isa<SelectInst>(U) || 
			isa<PHINode>(U)) {

		// Merge users of alias.
		UG->MergeUsers(U, UN->ele, U);
		// Track the next user.
		UG->usedValues.insert(U);
		Changed |= TrackNextUsers(UN, AS, UG);

		return Changed;
	}
	else if (BinaryOperator *BO = dyn_cast<BinaryOperator>(U)) {

		// FIXME: corner cases?
		Changed |= TrackInParallel(U, UN, AS, UG);
		return Changed;
	}
	// Ignore following instructions.
	else if (isa<ICmpInst>(U) || 
			isa<FCmpInst>(U) ||
			isa<SwitchInst>(U) ||
			isa<BranchInst>(U) ||
			isa<AllocaInst>(U) ||
			isa<InsertValueInst>(U) ||
			isa<ExtractValueInst>(U) ||
			isa<ConstantExpr>(U)
			) {

		return TrackNextUsers(UN, AS, UG);
	}
	// Any unrecognized cases are conservatively treated as sinks.
	else {
		// Convervative policy: assume any unrecognized special cases 
		// unsafe!!!
		OP<<"[Unrecognized user] "<<*U<<"\n";
		AS->SetSinkFlag(UN->ele->offset, UN->ele->size);
		return true;
	}

	return false;
}

// Further track the value when it is passed to other functions as 
// an argument, i.e., inter-procedural tracking.
// ArgNo: the index of the arg in the function callsite.
bool SafeAllocation::TrackArg(
		UserNode *UN, 
		unsigned ArgNo,
		AllocState *AS,
		UserGraph *UG) {

	bool Changed = false;
	CallInst *CI = dyn_cast<CallInst>(UN->U);

	// First, we quickly check the tracked value
	// is passed to the pre-defined sinking functions;
	// if not, we will track into the arg later.
	if (UN->ele->refHierarchy == -1 || 
			UN->ele->refHierarchy == 0) {

		for (Function *F : Ctx->Callees[CI]) {

			std::string funcname = F->getName().str();
			auto SFIter = Ctx->SinkFuncs.find(funcname);
			if (SFIter != Ctx->SinkFuncs.end()) {
				std::set<int>ArgSet = SFIter->second;
				if (ArgSet.find(ArgNo) != ArgSet.end()) {

#ifdef VERBOSE_SA
					OP<<"[Sink] Reaching "<<funcname<<"\n";
#endif

					AS->SetSinkFlag(UN->ele->offset, UN->ele->size);

					// No need to further track if the value is sunk.
					AS->AddFullySunkEle(UN->ele);
					AS->reachSink = true;
					Changed |= TrackNextUsers(UN, AS, UG);
					return Changed;
				}
			}
		}
	}

	// Now, we recursively track the value in called functions.
	AllocState ASMerge(AS);
	unsigned Count = 0;
	for (Function *F : Ctx->Callees[CI]) {

		std::string funcname = F->getName().str();

		// First do initialization analysis based on modeling 
		// if the called function is modeled.
		if (Ctx->InitFuncs.count(funcname)) {
			if (Ctx->InitFuncs[funcname].first == ArgNo) {
				if (Ctx->InitFuncs[funcname].second == -1) {
					AS->SetInitFlag(0, AS->size);
					AS->AddFullyInitedEle(UN->ele);
					continue;
				}

				Value *SizeArg = 
					CI->getArgOperand(Ctx->InitFuncs[funcname].second);
				ConstantInt *CSizeArg = 
					dyn_cast<ConstantInt>(SizeArg);
				if (CSizeArg) {
					unsigned Size = CSizeArg->getZExtValue();
					if (UN->ele->offset + Size > AS->size)
						Size = AS->size - UN->ele->offset;

					++Count;

					if (Count == 1) {
						ASMerge.SetInitFlag(UN->ele->offset, Size);
					}
					else {
						AllocState ASFork(AS);
						ASFork.SetInitFlag(UN->ele->offset, Size);
						// Merge allocation states.
						ASMerge.Merge(&ASFork);
					}

					Changed = true;
					if (Size >= UN->ele->size && UN->ele->size)
						AS->AddFullyInitedEle(UN->ele);
					if (ASMerge.AllBytesUnsafe(0, AS->size)) {
						AS->FastCopy(&ASMerge);
						return Changed;
					}

					continue;
				}
				// Aize is a variable.
				else {
					// If the variable size for initialization is the same as
					// the one of the value, the whole value is initialized.
					if (SizeArg == AS->sizeVar) {
						AS->AddFullyInitedEle(UN->ele);
						continue;
					}
					// Otherwise, we conservatively assume nothing is
					// initialized.
				}
			}
		}

		// Handle the cases that the called function is modeled and it
		// copy the tracked value to another one, e.g., memcpy.
		if (Ctx->CopyFuncs.count(funcname)) {
			if (std::get<0>(Ctx->CopyFuncs[funcname]) == ArgNo) {
				Value *Out = 
					CI->getArgOperand(std::get<1>(Ctx->CopyFuncs[funcname]));

				// Compute size.
				Value *SizeArg = 
					CI->getArgOperand(std::get<2>(Ctx->CopyFuncs[funcname]));
				unsigned Size = 0;
				if (ConstantInt *CSizeArg = 
						dyn_cast<ConstantInt>(SizeArg)) {
					Size = CSizeArg->getZExtValue();
					if (Size + UN->ele->offset > AS->size)
						Size = AS->size - UN->ele->offset;
				}
				else if (AS->isDynamic)
					Size = UN->ele->size;
				else
					Size = AS->size - UN->ele->offset;

				SafeAlias SA(Out, 0);
				std::set<SafeAliasSet *> AliasSets;
				SmallPtrSet<Value*, 8> Visited;
				if (!FindSafeAliasSets(&SA, &AliasSets, &Visited)) {
					AS->SetSinkFlag(UN->ele->offset, Size);
					if (Size >= UN->ele->size)
						AS->AddFullySunkEle(UN->ele);

					if (!AS->AllBytesUnsafe(0, AS->size)) 
						TrackNextUsers(UN, AS, UG);
					return true;
				}
				else {
					TrackAliasSet(UN, AS, &AliasSets, UG);
				}

				continue;
			}
		}

		// Skip functions that are comfirmed not sink.
		if (Ctx->NonSinkFuncs.count(funcname)) {
			continue;
		}
		// Get the real body of the called function from 
		// previously collected global function set.
		if (F->empty()) {
			auto FIter = Ctx->Funcs.find(F->getName());
			if (FIter != Ctx->Funcs.end()) {
				F = FIter->second;
			}
			else {
				// FIXME
				continue;
				// Assume unsafe if the called function is empty.
				AS->SetSinkFlag(UN->ele->offset, UN->ele->size);
				AS->AddFullySunkEle(UN->ele);

				if (!AS->AllBytesUnsafe(0, AS->size)) 
					TrackNextUsers(UN, AS, UG);
				return true;
			}
		}

		if (Argument *Arg = GetArgByArgNo(F, ArgNo)) {

			++Count;
			if (Count == 1) {
				Changed |= TrackValue(Arg, &ASMerge, UN->ele, Arg);
			}
			else {
				AllocState ASFork(AS);
				// Track the new store-to value.
				Changed |= TrackValue(Arg, &ASFork, UN->ele, Arg);
				// Merge allocation states.
				ASMerge.Merge(&ASFork);
			}

			if (ASMerge.AllBytesUnsafe(0, AS->size)) {
				AS->FastCopy(&ASMerge);
				return Changed;
			}

		}
	}
	// Do final merge.
	AS->FastCopy(&ASMerge);

	if (!AS->AllBytesUnsafe(0, AS->size))
		// Track the next user.
		Changed |= TrackNextUsers(UN, AS, UG);

	return Changed;
}

// Track the alias set of the tracked value.
bool SafeAllocation::TrackAliasSet(UserNode *UN, 
		AllocState *AS, 
		std::set<SafeAliasSet *> *AliasSets,
		UserGraph *UG) {

	if (AS->trackedStoreAlias->count(UN->U))
		return TrackNextUsers(UN, AS, UG);
	else
		AS->trackedStoreAlias->insert(UN->U);

	uint8_t *TmpFlagBytes = NULL;
	if (!AS->isDynamic) {
		TmpFlagBytes = (uint8_t *)malloc(UN->ele->size);
		memset(TmpFlagBytes, 
				ByteInited|!ByteSunk|!ByteUnsafe, UN->ele->size);
	}
	std::set<Value *>TrackedAlias;
	for (SafeAliasSet *AliasSet : *(AliasSets)) {
		if (!AliasSet->origin)
			continue;
		for (SafeAlias *Alias : AliasSet->aliasSet) {
			// This could be a spacial memory error.
			if (Alias->offset < 0)
				continue;

			if (TrackedAlias.count(Alias->alias))
				continue;
			else
				TrackedAlias.insert(Alias->alias);

			AllocState AliasAS(Alias->alias, 
					Alias->offset + UN->ele->size);
			AliasAS.trackedUsers = AS->trackedUsers;
			AliasAS.trackedStoreAlias = AS->trackedStoreAlias;
			// Default flags for other bytes.
			memset(AliasAS.bytesFlags, 
					ByteInited|!ByteSunk|!ByteUnsafe, AliasAS.size);
			// Copy flags.
			if (AS->isDynamic)
				memset(AliasAS.bytesFlags + Alias->offset, 
						!ByteInited|!ByteSunk|!ByteUnsafe,
						UN->ele->size);
			else
				memcpy(AliasAS.bytesFlags + Alias->offset, 
						AS->bytesFlags + UN->ele->offset, 
						UN->ele->size);
			Element AliasEle(UN->ele);
			AliasEle.offset = 0;
			AliasEle.size = AliasAS.size;
			AliasEle.refHierarchy = UN->ele->refHierarchy - 1;

			TrackValue(Alias->alias, &AliasAS, &AliasEle, UN->U);

			// merge the tracking result 
			if (!AS->isDynamic) {
				AllocState::Merge(TmpFlagBytes, 
						AliasAS.bytesFlags + Alias->offset,
						UN->ele->size);
			}

			AS->reachSink |= AliasAS.reachSink;
		}
	}
	if (!AS->isDynamic) {
		memcpy(AS->bytesFlags + UN->ele->offset,
				TmpFlagBytes, 
				UN->ele->size);
		free(TmpFlagBytes);
	}

	return true;
}

// When the tracked value is returned to callers, we furthur track
// each returned value on caller side.
bool SafeAllocation::TrackValueSet(std::set<Value *> *ValueSet, 
		AllocState *AS,
		Element *Ele) {

	bool Changed = false;
	AllocState ASMerge(AS);
	unsigned Count = 0;
	for (Value *V : *ValueSet) {

		++Count;

		if (Count == 1) {
			Changed |= TrackValue(V, &ASMerge, Ele, V);
		}
		else {
			AllocState ASFork(AS);
			Changed |= TrackValue(V, &ASFork, Ele, V);
			ASMerge.Merge(&ASFork);
		}

		if (ASMerge.AllBytesUnsafe(0, AS->size)) {
			AS->FastCopy(&ASMerge);
			return Changed;
		}
	}
	// Do final merge.
	AS->FastCopy(&ASMerge);

	return Changed;
}

// When the tracked value is loaded or stored, the branch is created,
// so we track the value in the branch and the next user in parallel. 
// After the parallel tracking, states will be merged.
bool SafeAllocation::TrackInParallel(Value *V, 
		UserNode *UN, 
		AllocState *AS, 
		UserGraph *UG) {

	bool Changed = false;
	bool TrackPath1 = !V->user_empty(), 
			 TrackPath2 = UN->nextUserNodes.size();

	if (TrackPath1) {

		AllocState ASFork(AS);
		Element Ele(UN->ele);
		// Update refHierarchy for loading and storing.
		if (isa<LoadInst>(UN->U))
			Ele.refHierarchy ++;
		else if (isa<StoreInst>(UN->U))
			Ele.refHierarchy --;
		else if (isa<BinaryOperator>(UN->U)) {
			// If the (recursive) pointer of the tracked value is 
			// binary-operated, we conseratively assume none of its bytes 
			// will be initialized.
			if (Ele.refHierarchy < 0)
				Ele.unknownOffset = true;
		}

		// Track the new value.
		Changed |= TrackValue(V, &ASFork, &Ele, UN->U);
		TrackPath2 = (TrackPath2 && 
				!ASFork.AllBytesUnsafe(0, AS->size));

		if (TrackPath2) {
			Changed |= TrackNextUsers(UN, AS, UG);
			// Merge allocation states.
			AS->Merge(&ASFork);
		}
		else 
			AS->FastCopy(&ASFork);
	}
	else 
		Changed |= TrackNextUsers(UN, AS, UG);

	return Changed;
}

// Function: finding safe alias sets. 
// If it cannot find all aliases or any alias is passed to 
// non-stack memory, it returns false, and we assume the 
// tracked value is sunk.
bool SafeAllocation::FindSafeAliasSets(
		SafeAlias *SA, 
		std::set<SafeAliasSet *> *AliasSets,
		SmallPtrSet<Value*, 8> *Visited,
		SafeAliasSet *AliasSet) {

	if (!AliasSet) {
		AliasSet = new SafeAliasSet();
		AliasSets->insert(AliasSet);
		SA = new SafeAlias(SA->alias, SA->offset);
	}
	AliasSet->aliasSet.insert(SA);

	SmallVector<SafeAlias *, 16> WorkList;

	Visited->insert(SA->alias);
	WorkList.push_back(SA);

	while (!WorkList.empty()) {

		SafeAlias *Alias = WorkList.pop_back_val();
		Value *AV = Alias->alias;
		int AO = Alias->offset;

		if (isa<ConstantInt>(AV) || isa<ConstantFP>(AV)) {
			continue;
		}
		else if (isa<GlobalVariable>(AV)) {
#ifdef SOUND_MODE
			return false;
#else
			continue;
#endif
		}

		if (isa<Argument>(AV) || 
				isa<AllocaInst>(AV)) {
			AliasSet->origin = AV;
			continue;
		}
		else if (CallInst *CI = dyn_cast<CallInst>(AV)) {
			if (Function *F = CI->getCalledFunction()) {
				if (Ctx->HeapAllocFuncs.count(F->getName().str())) {
					AliasSet->origin = AV;
					continue;
				}
			}
#ifdef SOUND_MODE
			return false;
#else
			continue;
#endif
		}

		if (GEPOperator *GO = dyn_cast<GEPOperator>(AV)) {
			// Check the base pointer only.
			if (!GO->hasAllConstantIndices())
				return false;
			int Offset = getGEPOffset(GO, DL);
			Value *B = GO->getOperand(0);
			SafeAlias *NewAlias = new SafeAlias(B, AO + Offset);
			AliasSet->aliasSet.insert(NewAlias);
			if (Visited->count(B) == 0) {
				Visited->insert(B);
				WorkList.push_back(NewAlias);
			}
			continue;
		}

		else if (CastInst *Cast = dyn_cast<CastInst>(AV)) {
			Value *B = Cast->getOperand(0);
			SafeAlias *NewAlias = new SafeAlias(B, AO);
			AliasSet->aliasSet.insert(NewAlias);
			if (Visited->count(B) == 0) {
				Visited->insert(B);
				WorkList.push_back(NewAlias);
			}
			continue;
		}

		// These aliases may come from different origins.
		SmallPtrSet<Value*, 8>NewOrigins;
		if (PHINode *PHI = dyn_cast<PHINode>(AV)) {
			for (unsigned i = 0; i != PHI->getNumIncomingValues(); ++i) {
				Value *P = PHI->getIncomingValue(i);
				NewOrigins.insert(P);
			}
		}

		else if (SelectInst *SI = dyn_cast<SelectInst>(AV)) {
			Value *T = SI->getTrueValue();
			Value *F = SI->getFalseValue();
			NewOrigins.insert(T);
			NewOrigins.insert(F);
		}

		// Handle new origins.
		if (NewOrigins.size() > 0) {
			unsigned Count = 0;
			for (Value *New : NewOrigins) {
				if (Visited->count(New) == 0) {
					Visited->insert(New);
					++Count;

					SafeAlias *NewAlias = new SafeAlias(New, AO);
					SafeAliasSet *NewAliasSet;
					if (Count < NewOrigins.size()) {
						NewAliasSet = new SafeAliasSet();
						AliasSets->insert(NewAliasSet);
						NewAliasSet->aliasSet.insert(AliasSet->aliasSet.begin(), 
								AliasSet->aliasSet.end());
						NewAliasSet->origin = AliasSet->origin;
					}
					else
						NewAliasSet = AliasSet;
					SmallPtrSet<Value*, 8> NewVisited;
					NewVisited.insert(Visited->begin(), Visited->end());
					if (!FindSafeAliasSets(NewAlias, AliasSets, 
								&NewVisited, NewAliasSet)) {
#ifdef SOUND_MODE
						return false;
#endif
					}
				}
			}

			continue;
		}

		// We conservatively assume that we cannot find aliases for other
		// cases, thus return false.
#ifdef SOUND_MODE
		return false;
#endif
	}

	return true;
}

// 
// Utils
//
Argument *SafeAllocation::GetArgByArgNo(Function *F, 
		unsigned ArgNo) {

	if (ArgNo >= F->arg_size())
		return NULL;

	unsigned idx = 0;
	Function::arg_iterator ai = F->arg_begin();
	while (idx != ArgNo) {
		++ai;
		++idx;
	}
	return ai;
}

int SafeAllocation::GetInsIdxInFunction(Instruction *I) {

	Function *F = I->getParent()->getParent();
	int Idx = 0;
	for (inst_iterator i = inst_begin(F), e = inst_end(F); 
			i != e; ++i) {
		++Idx;
		if (I == &*i)
			return Idx;
	}
	return -1;
}

// Output results
void SafeAllocation::WriteUnsafeAllocs(Module *M) {

	FILE *file = fopen(RESULTS_FILE, "a"); 
	std::string module = Ctx->ModuleMaps[M];
	if (module.substr(0, 2) == ("./"))
		module = module.substr(2);
	module = module.substr(0, module.size() - 3);
	fwrite(("module: " + module + "\n").c_str(), 
			module.size() + 9, 1, file);
	for (auto alloc : UnsafeAllocs) {
		fwrite(("\tfunction: " + alloc.first.str() + "\n").c_str(), 
				alloc.first.size() + 12, 1, file);
		for (StringRef Name : alloc.second) {
			fwrite(("\t\talloc: " + Name.str() + "\n").c_str(), 
					Name.size() + 10, 1, file);
		}
	}

	fclose(file);
}

void SafeAllocation::PrintStatistics() {
	OP<<"############## Result Statistics ##############\n";
	OP<<"# Number of functions: \t\t\t"<<Ctx->NumFunctions<<"\n";
	OP<<"# Number of static allocas: \t\t"<<Ctx->NumStaticAllocas<<"\n";
	OP<<"# Number of dynamic allocas: \t\t"<<Ctx->NumDynamicAllocas<<"\n";
	OP<<"# Number of unsafe allocas: \t\t"<<Ctx->NumUnsafeAllocas<<"\n";
	OP<<"# Number of static mallocs: \t\t"<<Ctx->NumStaticMallocs<<"\n";
	OP<<"# Number of dynamic mallocs: \t\t"<<Ctx->NumDynamicMallocs<<"\n";
	OP<<"# Number of unsafe mallocs: \t\t"<<Ctx->NumUnsafeMallocs<<"\n";
	OP<<"# Number of alloca bytes: \t\t"<<Ctx->NumAllocaBytes<<"\n";
	OP<<"# Number of unsafe alloca bytes: \t"<<Ctx->NumUnsafeAllocaBytes<<"\n";
	OP<<"# Number of malloc bytes: \t\t"<<Ctx->NumMallocBytes<<"\n";
	OP<<"# Number of unsafe malloc bytes: \t"<<Ctx->NumUnsafeMallocBytes<<"\n";
}


bool SafeAllocation::runOnFunction(Function *F) {

	return false;
}

// The iterative framework
bool SafeAllocation::doInitialization(Module *M) {

	DL = &(M->getDataLayout());
	IntPtrTy = DL->getIntPtrType(M->getContext());
	Int8Ty = Type::getInt8Ty(M->getContext());

	for (Function &F : *M) { 
		Ctx->NumFunctions++;
	}

	return false;
}

bool SafeAllocation::doFinalization(Module *M) {

	return false;
}

bool SafeAllocation::doModulePass(Module *M) {

	UnsafeAllocs.clear();

	// Start from allocation.
	for (Module::iterator f = M->begin(), fe = M->end(); f != fe; ++f) {
		Function *F = &*f;
		for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i) {
			// Stack allocation
			if (AllocaInst *AI = dyn_cast<AllocaInst>(&*i)) {
				SanitizeAlloca(AI);
			}
			// Heap allocation
			else if (CallInst *CI = dyn_cast<CallInst>(&*i)) {
				if (Function *F = CI->getCalledFunction()) {
					if (Ctx->HeapAllocFuncs.count(F->getName().str()))
						SanitizeMalloc(CI);
				}
			}
		}
	}

	// Write the info of unsafe allocations into the specified file.
	WriteUnsafeAllocs(M);

	return false;
}
