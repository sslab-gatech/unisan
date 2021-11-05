// SPDX-License-Identifier: MIT
//===-- SAStructs.cc - Date structures for UniSan---------------===//
// 
// This file implements a number of data structures for UniSan.
//
//===-----------------------------------------------------------===//

#include "SAStructs.h"
#include "Common.h"
#include "Config.h"



// 
// Implementation of Element.
//
bool Element::UpdateByGEP(GEPOperator *GEP, const DataLayout *DL) {

	Type *STy = GEP->getSourceElementType();
	// Get element index in bytes.
	if (!unknownOffset && GEP->hasAllConstantIndices()) {
		// Get element offset.
		offset += getGEPOffset(GEP, DL);
	}
	// If we can not statically know which field is accessed, label the
	// element as unknown. In this case, we conservatively assume the 
	// element is uninitialized and continue only reachability
	// analysis.
	else {
		unknownOffset = true;
	}

	// Compute element size.
	if (auto *I = dyn_cast<GetElementPtrInst>(GEP))
		size = DL->getTypeAllocSize(I->getResultElementType());
	else {
		SmallVector<Value*, 16> Idxs(GEP->idx_begin(), GEP->idx_end());
		Type *ETy =
			GetElementPtrInst::getIndexedType(STy, Idxs);
		size = DL->getTypeAllocSize(ETy);
	}

	return true;
}

//
// Implementation of AllocState.
//
void AllocState::Merge(AllocState *AS) {

	if (!isDynamic) {
		for (int i = 0; i < size; ++i) {
#ifdef SOUND_MODE
			// A byte is initialized only when it is initialized in all 
			// pathes.
			bytesFlags[i] &= (AS->bytesFlags[i] | ~ByteInited);
			// A byte is sunk as long as it is sunk in one of the pathes.
			bytesFlags[i] |= (AS->bytesFlags[i] & ByteSunk);
			// A byte is unsafe as long as it is unsafe in one of the 
			// pathes.
			bytesFlags[i] |= (AS->bytesFlags[i] & ByteUnsafe);
#else
			bytesFlags[i] |= (AS->bytesFlags[i] & ByteInited);
			bytesFlags[i] &= (AS->bytesFlags[i] | ~ByteSunk);
			bytesFlags[i] &= (AS->bytesFlags[i] | ~ByteUnsafe);
#endif
		}
	}

	reachSink |= AS->reachSink;
}

void AllocState::Merge(
		uint8_t *Dst, uint8_t *Src, unsigned Size) {
	for (int i = 0; i < Size; ++i) {
#ifdef SOUND_MODE
		// A byte is initialized only when it is initialized in all 
		// pathes.
		Dst[i] &= (Src[i] | ~ByteInited);
		// A byte is sunk as long as it is sunk in one of the pathes.
		Dst[i] |= (Src[i] & ByteSunk);
		// A byte is unsafe as long as it is unsafe in one of the 
		// pathes.
		Dst[i] |= (Src[i] & ByteUnsafe);
#else
		Dst[i] |= (Src[i] & ByteInited);
		Dst[i] &= (Src[i] | ~ByteSunk);
		Dst[i] &= (Src[i] | ~ByteUnsafe);
#endif
	}
}

// Copy flags.
void AllocState::FastCopy(AllocState *AS) {
	if (!isDynamic)
		memcpy(this->bytesFlags, AS->bytesFlags, AS->size);
	reachSink |= AS->reachSink;
}

void AllocState::SetInitFlag(uint64_t Offset, uint64_t Size) {

	// Conservatively assume dynamic allocations are never 
	// initialized.
	if (isDynamic)
		return;

	assert(Offset + Size <= size && "over size, cannot set init flag");
	uint64_t idx = Offset;
	while (idx < Offset + Size) {
		bytesFlags[idx] |= ByteInited;
		++idx;
	}

	// Update
	UpdateFlags(Offset, Size);
}

void AllocState::SetSinkFlag(uint64_t Offset, uint64_t Size) {

	if (isDynamic) {
		reachSink = true;
		return;
	}

	assert(Offset + Size <= size && "over size, cannot set sink flag");
	// If the element is unknown, conservatively think the whole
	// object may be leaked.
	uint64_t idx = Offset;
	unsigned sz = Offset + Size < size ? Offset + Size : size;
	while (idx < sz) {
		bytesFlags[idx] |= ByteSunk;
		++idx;
	}

	// Update
	UpdateFlags(Offset, Size);

	reachSink = true;
}

void AllocState::UpdateFlags(uint64_t Offset, uint64_t Size) {

	if (isDynamic)
		return;

	assert(Offset + Size <= size && "over size, cannot update flags");
	uint64_t idx = Offset;
	while (idx < Offset + Size) {
		if (!(bytesFlags[idx] & ByteInited) && 
				bytesFlags[idx] & ByteSunk)
			bytesFlags[idx] |= ByteUnsafe;
		++idx;
	}
}

bool AllocState::AllBytesUnsafe(uint64_t Offset, uint64_t Size) {

	if (isDynamic)
		return reachSink;

	assert(Offset + Size <= size && "over size");
	uint64_t idx = Offset;
	uint64_t Max = Offset + Size > size ? size : Offset + Size;
	while (idx < Max) {
		if (!(bytesFlags[idx] & ByteUnsafe))
			return false; 
		++idx;
	}
	return true;
}

bool AllocState::AllBytesSafe(uint64_t Offset, uint64_t Size) {

	if (isDynamic)
		return !reachSink;

	assert(Offset + Size <= size && "over size");
	uint64_t idx = Offset;
	while (idx < Offset + Size) {
		assert((bytesFlags[idx] & 0xf8) == 0);
		if ((bytesFlags[idx] & ByteUnsafe))
			return false; 
		++idx;
	}
	return true;
}

unsigned AllocState::NumUnsafeBytes() {

	if (isDynamic)
		return -1;

	unsigned idx = 0, Count = 0;
	while (idx < size) {
		if (bytesFlags[idx] & ByteUnsafe)
			++Count;
		++idx;
	}
	return Count;
}

unsigned AllocState::NumUninitedBytes() {

	if (isDynamic)
		return -1;

	unsigned idx = 0, Count = 0;
	while (idx < size) {
		if (!(bytesFlags[idx] & ByteInited))
			++Count;
		++idx;
	}
	return Count;
}

unsigned AllocState::NumSunkBytes() {

	if (isDynamic)
		return -1;

	unsigned idx = 0, Count = 0;
	while (idx < size) {
		if (bytesFlags[idx] & ByteSunk)
			++Count;
		++idx;
	}
	return Count;
}

bool AllocState::IsElementInited(Element *Ele) {

	if (Ele->unknownOffset || isDynamic)
		return false;

	uint64_t idx = Ele->offset;
	while (idx < Ele->offset + Ele->size) {
		if (!(bytesFlags[idx] & ByteInited))
			return false;
		++idx;
	}
	return true;
}

bool AllocState::AllBytesInited() {

	if (isDynamic)
		return false;

	uint64_t idx = 0;
	while (idx < size) {
		if (!(bytesFlags[idx] & ByteInited))
			return false;
		++idx;
	}
	return true;
}

bool AllocState::AllBytesSunk() {

	if (isDynamic)
		return reachSink;

	uint64_t idx = 0;
	while (idx < size) {
		if (!(bytesFlags[idx] & ByteSunk))
			return false;
		++idx;
	}
	return true;
}

bool AllocState::IsElementSunk(Element *Ele) {

	if (Ele->unknownOffset || isDynamic)
		return reachSink;

	uint64_t idx = Ele->offset;
	while (idx < Ele->offset + Ele->size) {
		if (!(bytesFlags[idx] & ByteSunk))
			return false;
		++idx;
	}
	return true;
}

void AllocState::PrintUninitedBytes() {

	if (isDynamic)
		return;

	OP <<"Uninitialized bytes:\n";
	uint64_t idx = 0;
	while (idx < size) {
		if (!(bytesFlags[idx] & ByteInited))
			OP<<idx<<" ";
		++idx;
	}
	OP<<"\n";
}

void AllocState::PrintSunkBytes() {

	if (isDynamic)
		return;

	OP <<"Sunk bytes:\n";
	uint64_t idx = 0;
	while (idx < size) {
		if (bytesFlags[idx] & ByteSunk)
			OP<<idx<<" ";
		++idx;
	}
	OP<<"\n";
}

void AllocState::PrintFlagBytes() {

	if (isDynamic)
		return;

	OP <<"Flag bytes:\n";
	uint64_t idx = 0;
	while (idx < size) {
		OP<< format("%d ", bytesFlags[idx]);
		++idx;
	}
	OP<<"\n";
}


// 
// Implementation of BBNode, UserNode, and UserGraph.
//
void BBNode::Insert(UserNode *UN) {

	std::list<UserNode *>::iterator it = userNodes.begin();
	// The argument is not in the basicblock.
	if (isa<Argument>((*it)->U))
		++it;
	std::list<UserNode *>::iterator pre = it;
	for (BasicBlock::iterator I = BB->begin(), E = BB->end();
			I != E; ++I) {
		if (I == UN->U) {
			// Already inserted
			if (UN->U == (*it)->U) {
				delete UN;
				return;
			}
			UN->nextUserNodes.insert(*it);
			(*it)->preUserNodes.insert(UN);
			if (it != userNodes.begin()) {
				(*pre)->nextUserNodes.erase(*it);
				(*pre)->nextUserNodes.insert(UN);
				UN->preUserNodes.insert(*pre);
			}
			userNodes.insert(it, UN);
			return;
		}
		else if (I == (*it)->U) {
			pre = it;
			++it;
			if (it == userNodes.end()) {
				(*pre)->nextUserNodes.insert(UN);
				UN->preUserNodes.insert(*pre);
				userNodes.insert(it, UN);
				return;
			}
		}
	}
}

// Put the users of the given value into the corresponding BBNode.
void UserGraph::PutUserInBB(Value *V, Element *Ele, 
		Value *StartUser, bool IsNew) {

	// Get all reachable basic blocks of StartUser.
	BasicBlock *StartBB = GetBasicBlock(V);
	std::set<BasicBlock *>BBs;
	GetReachableBBs(StartUser, &BBs);
	// Put UserNodes in corresponding BBNodes.
	for (Value::user_iterator ui = V->user_begin(), ue = V->user_end();
			ui != ue; ++ui) {

		Instruction *I = dyn_cast<Instruction>(*ui);
		//FIXME
		if (!I)
			continue;
		if (!BBs.count(I->getParent()))
			continue;

		if (CallInst *CI = dyn_cast<CallInst>(I)) {
			if (Function *F = CI->getCalledFunction()) {
				if (F->getName() == "llvm.lifetime.end" ||
						F->getName() == "llvm.lifetime.start")
					continue;
			}
		}
		// If the user is in the same block as StartUser.
		if (StartBB == I->getParent()) {
			// Only consider users dominated by StartUser.
			if (!Dominate(StartUser, I, StartBB))
				continue;
		}

		UserNode *UN = new UserNode(*ui, Ele);
		BBNode *BBN;
		if (involvedBBs.find(I->getParent()) != involvedBBs.end()) {
			BBN = involvedBBs[I->getParent()];
		}
		else {
			BBN = new BBNode();
			BBN->BB = I->getParent();
			involvedBBs[I->getParent()] = BBN;
		}
		UN->BBN = BBN;

		if (BBN->userNodes.size()) {
			BBN->Insert(UN);
		}
		else {
			BBN->userNodes.push_front(UN);
		}
	}
}

void UserGraph::GetReachableBBs(Value *V, 
		std::set<BasicBlock *> *BBs) {

	BasicBlock *CurBB = GetBasicBlock(V);
	BBs->insert(CurBB);

	SmallPtrSet<BasicBlock*, 8> Visited;
	SmallVector<BasicBlock*, 8> WorkList;

	Visited.insert(CurBB);
	WorkList.push_back(CurBB);

	while (!WorkList.empty()) {
		BasicBlock *BB = WorkList.pop_back_val();
		const TerminatorInst *TI = BB->getTerminator();
		for (unsigned I = 0, NS = TI->getNumSuccessors(); 
				I < NS; ++I) {
			BasicBlock *Succ = TI->getSuccessor(I);
			if (Visited.count(Succ))
				continue;
			else {
				Visited.insert(Succ);
				BBs->insert(Succ);
				WorkList.push_back(Succ);
			}
		}
	}
}

// Connect BBNodes into UserGraph.
void UserGraph::ConnectUserNodes(BBNode *From, 
		BasicBlock *ToSucc, BBPairSet *BBSet) {

	if (BBSet->find(std::make_pair(From, ToSucc)) != BBSet->end())
		return;
	else BBSet->insert(std::make_pair(From, ToSucc));

	std::set<BasicBlock *>SuccSet;
	const TerminatorInst *TI = ToSucc->getTerminator();
	for (unsigned I = 0, NS = TI->getNumSuccessors(); I < NS; ++I) {
		SuccSet.insert(TI->getSuccessor(I));
	}
	for (BasicBlock *Succ : SuccSet) {
		//BasicBlock *Succ = TI->getSuccessor(I);
		if (involvedBBs.find(Succ) != involvedBBs.end()) {
			From->userNodes.back()->nextUserNodes.insert(
					involvedBBs[Succ]->userNodes.front());
			involvedBBs[Succ]->userNodes.front()->preUserNodes.insert(
					From->userNodes.back());
			ConnectUserNodes(involvedBBs[Succ], Succ, BBSet);
		}
		else
			ConnectUserNodes(From, Succ, BBSet);
	}
}

// Disconnect BBNodes.
void UserGraph::DisconnectBBNodes(BBNode *From) {

	if (!From->userNodes.back()->nextUserNodes.size())
		return;

	std::set<UserNode *>NextUserNodes = 
		From->userNodes.back()->nextUserNodes;
	From->userNodes.back()->nextUserNodes.clear();

	for (UserNode *Next : NextUserNodes) {
		Next->preUserNodes.clear();
		DisconnectBBNodes(Next->BBN);
	}
}

// Merge the users of the given value into this graph.
void UserGraph::MergeUsers(Value *V, Element *Ele, 
		Value *StartUser) {

	// Disconnect nodes in the old graph.
	DisconnectBBNodes(FirstBBN);
	// Put users in basic blocks.
	PutUserInBB(V, Ele, StartUser, false);
	//Instruction *I = dyn_cast<Instruction>(StartUser);

	// Re-connect user nodes into a new user graph
	//BBNode *FirstBBN = involvedBBs[I->getParent()];
	BBPairSet BBSet;
	ConnectUserNodes(FirstBBN, FirstBBN->BB, &BBSet);
}

void UserGraph::PrintUserNode(UserNode *UN, 
		std::set<UserNode *> *Printed) {

	if (Printed->count(UN))
		return;
	else
		Printed->insert(UN);

	if (!UN->nextUserNodes.size())
		return;

	OP<<*(UN->U)<<" --> ";
	for (UserNode *UN : UN->nextUserNodes) {
		OP<<"\n\t>>>"<<*(UN->U);
	}
	OP<<"\n";

	for (UserNode *Next : UN->nextUserNodes) {
		PrintUserNode(Next, Printed);
	}
}

void UserGraph::PrintGraph(Value *V) {

	OP<<"[UserGraph] START\n";
	if (V->use_empty())
		return;

	std::set<UserNode *>Printed;
	PrintUserNode(FirstUN, &Printed);
	OP<<"[UserGraph] END\n";
}
