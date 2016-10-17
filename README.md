# UniSan: Proactive Kernel Memory Initialization to Eliminate Data Leakages

UniSan aims to eliminate all information leaks caused by uninitialized data reads in OS kernels. OS kernels employ security mechanisms, kASLR and StackGuard, to prevent code-reuse and privilege escalation attacks. However, the common information leaks in OS kernels render these security mechanisms ineffective. Clearly, information leaks may also directly leak sensitive data such as cryptographic keys in OS kernels. 
According to a previous study and our study, most kernel information leaks are caused by uninitialized data reads. 

UniSan is a novel, compiler-based approach that uses byte-level, flow-sensitive, context-sensitive, and field-sensitive initialization analysis and reachability analysis to check whether an allocation has been fully initialized when it leaves kernel space; if not, it automatically instruments the kernel to zero-initialize this allocation. UniSan is robust because its zero-initialization to allocations would not break original semantics. Also, UniSan is conservative to eliminate false negatives. We implemented UniSan as passes of LLVM. By applying it to the latest Linux kernel and Android kernel, we confirmed that UniSan can successfully prevent known and many new uninitialized data leak vulnerabilities, with a negligible performance overhead.

## More details
* UniSan paper (ACM CCS'16): http://www.cc.gatech.edu/~klu38/publications/unisan-ccs16.pdf
* Webpage for UniSan: https://sslab.gtisc.gatech.edu/pages/unisan.html

## How to build UniSan
  ```sh
  $ cd unisan
  # Build LLVM that contains the instrumentation pass of UniSan
  $ cd llvm-3.7.1
  $ ./build-llvm.sh
  # Build the analysis pass of UniSan
  $ cd ../analysis
  $ make
  # Now, the UniSan binary is located at analysis/build/unisan
  ```
 
## How to use UniSan
### Use UniSan's analysis pass
```sh
# If you want to analyze a list of bitcode file, put the paths of the bitcode files in a list file, e.g., "bitcode.list". Then run:
$ ./unisan -safe-alloc @bitcode.list
# If you want to analyze a single bitcode file, say "test.bc", run:
$ ./unisan -safe-alloc test.bc
# The statistics are printed out on stdout, while the info of unsafe allocations is saved in a temporary file: /tmp/UnsafeAllocs.txt.
```
### Use UniSan's instrumentation pass
1. Use the "clang" of UniSan, i.e., the one you just built in llvm-3.7.1.
If you use the LLVMLinux project, this step can be done by editing "CLANG" and "LLC" in file "llvmlinux/toolchain/clang/clang-native.mk". 
2. Enable the instrumentation pass of UniSan: use option "-fsanitize=alloc"
3. Make sure you have run UniSan's analysis pass. Once you run clang to compile your code, UniSan will secure the unsafe allocations based on /tmp/UnsafeAllocs.txt. 

### Locating UniSan's code
* Analysis pass: unisan/analysis/src/lib/
* Instrumentation pass: llvm-3.7.1/llvm/lib/Transforms/Instrumentation/AllocSanitizer.cpp

### Contributors
* [Kangjie Lu]
* [Chengyu Song]
* [Taesoo Kim]
* [Wenke Lee]

[Kangjie Lu]: <http://www.cc.gatech.edu/~klu38>
[Chengyu Song]: <http://www.cs.ucr.edu/~csong>
[Taesoo Kim]: <https://taesoo.gtisc.gatech.edu>
[Wenke Lee]: <http://wenke.gtisc.gatech.edu>
