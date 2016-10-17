#ifndef _SAFE_ALLOC_STRUCTS_H
#define _SAFE_ALLOC_STRUCTS_H

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Operator.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Format.h>
#include <set>
#include <list>
#include <map>
#include <string>


using namespace llvm;


// The element (i.e., field) of the tracked object.
struct Element {
	// The offset(in bytes) of current element into the base of the 
	// tracked object. It can be negative.
	int offset;
	// The size of the element.
	unsigned size;
	// Reference hierarchy is to understand if a pointer (pointing to 
	// the current element) is directly or indirectly (recursively) 
	// pointing to the tracked object. The “indirectness” is decreased 
	// by one by LoadInst; but increased by one by StoreInst.
	int refHierarchy;
	// If a GEP instruciton does not have constant indices, the 
	// obtained element will be unknown. In this case, we will label it 
	// as unknown to be conservative, and do not do initialization 
	// analysis but only reachability analysis for it.
	bool unknownOffset;

	// The upper element that contains current element.
	Element *parentEle;


	Element() {
		parentEle = NULL;
	}

	Element(Element *Ele) {
		memcpy(this, Ele, sizeof(Element));
	}

	Element(Value *Alloc, const DataLayout *DL) {
		// Stack allocation
		if (AllocaInst *AI = dyn_cast<AllocaInst>(Alloc)) {
			// Static allocation
			if (AI->isStaticAlloca()) {
				Type *allocTy = AI->getAllocatedType();
				unsigned tySize = DL->getTypeAllocSize(allocTy);
				unsigned arraySize = 
					cast<ConstantInt>(AI->getArraySize())->getZExtValue();
				size = tySize * arraySize;;
				unknownOffset = false;
			}
			// Dynamic alloaction
			else {
				size = 0;
				unknownOffset = true;
			}
		}
		// Heap allocation
		else if (CallInst *CI = dyn_cast<CallInst>(Alloc)){
			Value *SizeArg = CI->getArgOperand(0);
			ConstantInt *CSizeArg = dyn_cast<ConstantInt>(SizeArg);
			// Static malloc -- its size is constant
			if (CSizeArg) {
				size = CSizeArg->getZExtValue();
				unknownOffset = false;
			}
			// Dynamic malloc
			else {
				size = 0;
				unknownOffset = true;
			}
		}
		else 
			report_fatal_error("Unrecognized allocation");

		offset = 0;
		// Originally, it is a pointer to the allocated memory.
		refHierarchy = -1;
		parentEle = NULL;
	}

	// Set the offset and size of current element based on the 
	// given GEP instruction.
	bool UpdateByGEP(GEPOperator *GEP, const DataLayout *DL);

};

struct SafeAlias {
	Value *alias;
	// The offset of the being tracked value into this alias.
	// -1 indicates the offset is unknown.
	int offset;

	SafeAlias(Value *A, int O) {
		alias = A;
		offset = O;
	}
};

struct SafeAliasSet {
	// The origin of alias, e.g., the allocation.
	Value *origin;
	std::set<SafeAlias *> aliasSet;

	SafeAliasSet() {
		origin = NULL;
	}
};

static void ReleaseAliasSets(std::set<SafeAliasSet *> *AliasSets) {

	std::set<SafeAlias *>DeletedSet;
	for (SafeAliasSet *AliasSet : *AliasSets) {
		for (SafeAlias *Alias : AliasSet->aliasSet) {
			if (!DeletedSet.count(Alias)) {
				DeletedSet.insert(Alias);
				delete Alias;
			}
		}
		delete AliasSet;
	}
}

// 
// The flags of tracked bytes.
// Do not use enum to reduce memory usage.
//
#define  ByteInited 0x1	// the byte is initialized
#define  ByteSunk		0x2	// the byte reaches a sink
// the byte is unsafe--it could be sunk without being initialized
#define  ByteUnsafe 0x4	


//
// Bookkeeping of the tracked allocation.
//
struct AllocState {
	// The allocation instruction
	Value *allocIns;
	// The flags indicating initialization, sinking, and safety
	uint8_t *bytesFlags;
	// Size of the allocation
	int size;
	// Non-constant size value
	Value *sizeVar;
	// If it reaches sink functions
	bool reachSink;

	// Dynamic allocations whose size cannot be decided statically.
	bool isDynamic;

	// All elements
	std::set<Element *>Eles;

	// The set of fully inited elements
	std::set<Element *>fullyInitedEles;

	// The set of fully sunk elements
	std::set<Element *>fullySunkEles;

	// The set of already tracked values, to prevent cycle
	std::map<User *, std::set<uint8_t *>> *trackedUsers;

	// The set of already tracked alias (the storeinst)
	std::set<Value *> *trackedStoreAlias;

	const DataLayout *DL;

	// Constructors
	AllocState(Instruction *I, const DataLayout *DL) {

		this->DL = DL;
		allocIns  = I;
		// Stack allocations
		if (AllocaInst *AI = dyn_cast<AllocaInst>(I)) {
			if (AI->isStaticAlloca()) {
				Type *allocTy = AI->getAllocatedType();
				unsigned tySize = DL->getTypeAllocSize(allocTy);
				unsigned arraySize = 
					cast<ConstantInt>(AI->getArraySize())->getZExtValue();
				size = tySize * arraySize;
				// Initialize flags of all bytes.
				bytesFlags = (uint8_t *)malloc(size);
				memset(bytesFlags, 
						!ByteInited|!ByteSunk|!ByteUnsafe, size);
				isDynamic = false;
			}
			else {
				size = 0;
				bytesFlags = NULL;
				isDynamic = true;
			}

			sizeVar = NULL;
		}
		// Heap allocations
		else if (CallInst *CI = dyn_cast<CallInst>(I)){
			Value *SizeArg = CI->getArgOperand(0);
			ConstantInt *CSizeArg = dyn_cast<ConstantInt>(SizeArg);
			if (CSizeArg) {
				size = CSizeArg->getZExtValue();
				if (size > 0) {
					bytesFlags = (uint8_t *)malloc(size);
					memset(bytesFlags, 
							!ByteInited|!ByteSunk|!ByteUnsafe, size);
				}
				else
					bytesFlags = NULL;
				isDynamic = false;
				sizeVar = NULL;
			}
			else {
				size = 0;
				bytesFlags = NULL;
				isDynamic = true;
				sizeVar = SizeArg;
			}
		}
		else 
			report_fatal_error("Unrecognized allocation");

		reachSink = false;

		trackedUsers = new std::map<User *, std::set<uint8_t *>>();
		trackedStoreAlias = new std::set<Value *>();
	}

	// Duplicate state
	AllocState(AllocState *AS) {
		DL = AS->DL;
		allocIns  = AS->allocIns;
		size = AS->size;
		reachSink = AS->reachSink;
		isDynamic = AS->isDynamic;
		sizeVar = AS->sizeVar;

		if (!isDynamic) {
			bytesFlags = (uint8_t *)malloc(size);
			memcpy(bytesFlags, AS->bytesFlags, size);
		}
		else
			bytesFlags = NULL;

		trackedUsers = AS->trackedUsers;
		trackedStoreAlias = AS->trackedStoreAlias;
		fullyInitedEles = AS->fullyInitedEles;
		fullySunkEles = AS->fullySunkEles;
	}

	AllocState(Value *V, unsigned Size) {

		size = Size;
		bytesFlags = (uint8_t *)malloc(size);
		allocIns  = V;
		isDynamic = false;
		reachSink = false;
		sizeVar = NULL;
	}

	~AllocState() {
		if (bytesFlags)
			free(bytesFlags);
	}

	void Release() {
		if (trackedUsers) {
			for (auto U : *trackedUsers) {
				for (uint8_t * M : U.second)
					free(M);
			}
			delete trackedUsers;
			trackedUsers = NULL;
		}

		delete trackedStoreAlias;

		for (Element *Ele : Eles)
			delete Ele;
	}

	// Conservatively merge states
	void Merge(AllocState *AS);
	static void Merge(uint8_t *Dst, uint8_t *Src, unsigned Size);
	// Fast copy of bytesFlags
	void FastCopy(AllocState *AS);
	void ResetElement(Element *Ele);

	// Set and update flags
	void SetInitFlag(uint64_t Offset, uint64_t Size);
	void SetSinkFlag(uint64_t Offset, uint64_t Size);
	void UpdateFlags(uint64_t Offset, uint64_t Size);

	// Check flags
	bool AllBytesInited();
	bool AllBytesSunk();
	bool AllBytesUnsafe(uint64_t Offset, uint64_t Size);
	bool AllBytesSafe(uint64_t Offset, uint64_t Size);
	bool IsElementInited(Element *Ele);
	bool IsElementSunk(Element *Ele);

	// Check numbers
	unsigned NumUnsafeBytes();
	unsigned NumUninitedBytes();
	unsigned NumSunkBytes();

	// Print state
	void PrintUninitedBytes();
	void PrintSunkBytes();
	void PrintFlagBytes();


	// Operations
	void AddFullyInitedEle(Element *Ele) {
		fullyInitedEles.insert(Ele);
	}

	void AddFullySunkEle(Element *Ele) {
		fullySunkEles.insert(Ele);
	}

	bool IsFullyInitedEle(Element *Ele) {
		if (fullyInitedEles.count(Ele))
			return true;

		if (!Ele->parentEle)
			return false;
		return IsFullyInitedEle(Ele->parentEle);
	}

	bool IsFullySunkEle(Element *Ele) {
		if (fullySunkEles.count(Ele))
			return true;

		if (!Ele->parentEle)
			return false;
		return IsFullySunkEle(Ele->parentEle);
	}

};


//
// Maintain the user graph of a tracked value.
//
// Basic block node
struct BBNode;

struct UserNode {
	UserNode(Value *U, Element *Ele) {
		this->U = U;
		ele = Ele;
	}
	Value *U;
	std::set<UserNode *>nextUserNodes;
	std::set<UserNode *>preUserNodes;

	Element *ele;

	BBNode *BBN;

	std::set<uint8_t *>flagsCaches;
};

// Wrapper of BasicBlock
struct BBNode {
	BasicBlock *BB;
	// Do not change order
	std::list<UserNode *>userNodes;

	void Insert(UserNode *UN);
};

typedef std::map<BasicBlock *, BBNode *> BBMap;
typedef std::set< std::pair<BBNode *, BasicBlock *> > BBPairSet;

struct UserGraph {

	UserNode *FirstUN;
	BBNode *FirstBBN;

	BBMap involvedBBs;

	// The set of being used values, including alias
	std::set<Value *> usedValues;

	// Build the user graph of the given value
	UserGraph(Value *V, Value *StartUser, Element *Ele) {

		// No users
		if (V->use_empty()) {
			return;
		}

		usedValues.insert(V);

		FirstUN = new UserNode(V, Ele);

		// The BasicBlock of the value.
		// The value may not be belonged to any BasicBlock, 
		// e.g., argument.
		FirstBBN = new BBNode();
		FirstUN->BBN = FirstBBN;
		FirstBBN->BB = GetBasicBlock(V);
		involvedBBs[FirstBBN->BB] = FirstBBN;

		PutUserInBB(V, Ele, StartUser);

		if (FirstBBN->userNodes.size()) { 
			FirstUN->nextUserNodes.insert(FirstBBN->userNodes.front());
			FirstBBN->userNodes.front()->preUserNodes.insert(FirstUN);
		}
		FirstBBN->userNodes.push_front(FirstUN);

		// Connect BBNodes
		BBPairSet BBSet;
		ConnectUserNodes(FirstBBN, FirstBBN->BB, &BBSet);
	}

	~UserGraph() {

		for (auto BBI : involvedBBs) {
			for (UserNode *UN : BBI.second->userNodes) {
				for (uint8_t *Flags : UN->flagsCaches)
					free(Flags);
				delete UN;
			}
			delete BBI.second;
		}
	}

	BasicBlock *GetBasicBlock(Value *V) {

		BasicBlock *BB = NULL;
		if (Instruction *I = dyn_cast<Instruction>(V))
			BB = I->getParent();
		else if (Argument *Arg = dyn_cast<Argument>(V))
			BB = &(Arg->getParent()->getEntryBlock());
		else {
			User *U = dyn_cast<User>(V);
			assert (!U->use_empty());
			if (Instruction *I = dyn_cast<Instruction>(U->user_back()))
				BB = I->getParent();
			else
				report_fatal_error("Unknown type of value");
		}

		return BB;
	}

	bool Dominate(Value *A, Value *B, BasicBlock *BB) {
		if (A == B)
			return false;
		if (isa<Argument>(A))
			return true;

		assert(isa<Instruction>(B));

		Instruction *IA = dyn_cast<Instruction>(A);
		if (!IA) {
			User *U = dyn_cast<User>(A);
			IA = dyn_cast<Instruction>(U->user_back());
		}

		for (BasicBlock::iterator i = BB->begin(), 
				e = BB->end(); i != e; ++i) {
			Instruction *I = &*i;
			if (I == IA)
				return true;
			if (I == B)
				return false;
		}

		return false;
	}

	// Get all reachable basic blocks of the value.
	void GetReachableBBs(Value *V, std::set<BasicBlock *> *BBs);
	// Put the users of the given value into the corresponding BBNode.
	void PutUserInBB(Value *V, Element *Ele,
			Value *StartUser, bool IsNew = true);

	// Connect user nodes into UserGraph.
	void ConnectUserNodes(BBNode *From, BasicBlock *ToSucc, 
			BBPairSet *BBSet);

	// Disconnect basic block nodes.
	void DisconnectBBNodes(BBNode *From);

	// Merge the users of the given value into this graph.
	void MergeUsers(Value *V, Element *Ele, Value *StartUser);

	// Print user graph.
	void PrintUserNode(UserNode *UN, std::set<UserNode *> *Printed);
	void PrintGraph(Value *V);
};

// Given a GEP insn or GEP const expr, compute its byte-offset
// The function will resolve nested GEP constexpr, but will not 
// resolve nested GEP instruction.
static int64_t getGEPOffset(const Value* value, 
		const DataLayout* dataLayout)
{
	// Assume this function always receives GEP value.
	const GEPOperator* gepValue = dyn_cast<GEPOperator>(value);
	assert(gepValue != NULL && 
			"getGEPOffset receives a non-gep value!");
	assert(dataLayout != nullptr && 
			"getGEPOffset receives a NULL dataLayout!");

	int64_t offset = 0;
	const Value* baseValue = 
		gepValue->getPointerOperand()->stripPointerCasts();
	// If we have yet another nested GEP const expr, accumulate its 
	// offset. The reason why we don't accumulate nested GEP 
	// instruction's offset is that we aren't required to. Also, it 
	// is impossible to do that because we are not sure if the 
	// indices of a GEP instruction contains all-consts or not.
	if (const ConstantExpr* cexp = dyn_cast<ConstantExpr>(baseValue))
		if (cexp->getOpcode() == Instruction::GetElementPtr)
			offset += getGEPOffset(cexp, dataLayout);

	Type* ptrTy = gepValue->getPointerOperand()->getType();
	SmallVector<Value*, 4> indexOps(gepValue->op_begin() + 1, 
			gepValue->op_end());
	// Make sure all indices are constants.
	for (unsigned i = 0, e = indexOps.size(); i != e; ++i)
	{
		if (!isa<ConstantInt>(indexOps[i]))
			indexOps[i] = 
				ConstantInt::get(Type::getInt32Ty(ptrTy->getContext()), 0);
	}

	offset += dataLayout->getIndexedOffset(ptrTy, indexOps);

	return offset;
}


#endif

