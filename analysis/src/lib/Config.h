#ifndef _SACONFIG_H
#define _SACONFIG_H


#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>

//
// Configurations for compilation.
//
//#define VERBOSE_SA 1
//#define DEBUG_SA 1
#define SOUND_MODE 1

#define RESULTS_FILE "/tmp/UnsafeAllocs.txt"


// Setup sinking functions here.
static void SetSinkFuncs(
		std::unordered_map<std::string, std::set<int>> &SinkFuncs) {

	SinkFuncs["copy_to_user"].insert(1);
	SinkFuncs["__copy_to_user"].insert(1);
	SinkFuncs["nla_put"].insert(3);
	SinkFuncs["put_user"].insert(0);
	SinkFuncs["send_signal"].insert(1);
	SinkFuncs["__send_signal"].insert(1);
	SinkFuncs["vfs_write"].insert(1);
	SinkFuncs["sock_sendmsg"].insert(1);
}


// Setup functions that nerver sink.
static void SetNonSinkFuncs(
		std::set<std::string> &NonSinkFuncs) {

	std::string NonSinkFN[] = {
		"set_bit",
		"clear_bit",
		"__copy_from_user",
		"memset",
		"llvm.memset.p0i8.i64",
		"fpsimd_load_state",
		"get_user_pages_fast",
		"probe_kernel_read",
		"save_stack_trace_regs",
		"ce_aes_ccm_auth_data",
		"llvm.lifetime.start",
		"llvm.lifetime.end",
		"vsscanf",
		"test_and_set_bit",
		"llvm.cttz.i64",
		"__cpu_flush_user_tlb_range",
		"__local_cpu_flush_user_tlb_range",
		"strchr",
		"memchr",
		"strrchr",
		"llvm.ctlz.i64",
		"llvm.ctlz.i32",
		"llvm.uadd.with.overflow.i64",
		"llvm.uadd.with.overflow.i32",
		"llvm.bswap.i32",
		"llvm.bswap.i64",
		"ce_aes_ctr_encrypt",
		"ce_aes_ccm_final",
		"ce_aes_ccm_decrypt",
		"llvm.va_start",
		"llvm.va_end",
		"llvm.va_copy",
		"nl80211_parse_mesh_config",
		"test_and_clear_bit",
		"kfree",
	};

	for (auto F : NonSinkFN) {
		NonSinkFuncs.insert(F);
	}
}

// Setup functions that initialize/overwrite target values.
static void SetInitFuncs(
		std::map<std::string, std::pair<uint8_t, int8_t>> &InitFuncs) {

	InitFuncs["memcpy"] = std::make_pair(0, 2);
	InitFuncs["__memcpy"] = std::make_pair(0, 2);
	InitFuncs["llvm.memcpy.p0i8.p0i8.i32"] = std::make_pair(0, 2);
	InitFuncs["llvm.memcpy.p0i8.p0i8.i64"] = std::make_pair(0, 2);
	InitFuncs["memmove"] = std::make_pair(0, 2);
	InitFuncs["llvm.memmove.p0i8.p0i8.i32"] = std::make_pair(0, 2);
	InitFuncs["llvm.memmove.p0i8.p0i8.i64"] = std::make_pair(0, 2);
	InitFuncs["memset"] = std::make_pair(0, 2);
	InitFuncs["llvm.memset.p0i8.i32"] = std::make_pair(0, 2);
	InitFuncs["llvm.memset.p0i8.i64"] = std::make_pair(0, 2);
	InitFuncs["strncpy"] = std::make_pair(0, 2);
	InitFuncs["strncpy_from_user"] = std::make_pair(0, 2);
	InitFuncs["copy_from_user"] = std::make_pair(0, 2);
	InitFuncs["__copy_from_user"] = std::make_pair(0, 2);
	InitFuncs["kfree"] = std::make_pair(0, -1);
	InitFuncs["vfree"] = std::make_pair(0, -1);
	InitFuncs["kfree_skb"] = std::make_pair(0, -1);
	InitFuncs["free"] = std::make_pair(0, -1);
}

// Setup functions that copy/move values.
static void SetCopyFuncs(
		std::map<std::string, std::tuple<uint8_t, uint8_t, int8_t>> 
		&CopyFuncs) {

	CopyFuncs["memcpy"] = std::make_tuple(1, 0, 2);
	CopyFuncs["llvm.memcpy.p0i8.p0i8.i32"] = std::make_tuple(1, 0, 2);
	CopyFuncs["llvm.memcpy.p0i8.p0i8.i64"] = std::make_tuple(1, 0, 2);
	CopyFuncs["strncpy"] = std::make_tuple(1, 0, 2);
	CopyFuncs["memmove"] = std::make_tuple(1, 0, 2);
	CopyFuncs["llvm.memmove.p0i8.p0i8.i32"] = std::make_tuple(1, 0, 2);
	CopyFuncs["llvm.memmove.p0i8.p0i8.i64"] = std::make_tuple(1, 0, 2);
}

// Setup functions for heap allocations.
static void SetHeapAllocFuncs(
		std::set<std::string> &HeapAllocFuncs){

	std::string HeapAllocFN[] = {
		"__kmalloc",
		"__vmalloc",
		"vmalloc",
		"krealloc",
		"devm_kzalloc",
		"vzalloc",
		"malloc",
		"kmem_cache_alloc",
		"__alloc_skb",
	};

	for (auto F : HeapAllocFN) {
		HeapAllocFuncs.insert(F);
	}
}


#endif
