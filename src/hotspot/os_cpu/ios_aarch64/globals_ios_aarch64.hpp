#ifndef OS_CPU_IOS_AARCH64_GLOBALS_IOS_AARCH64_HPP
#define OS_CPU_IOS_AARCH64_GLOBALS_IOS_AARCH64_HPP

// Sets the default values for platform dependent flags used by the runtime system.
// (see globals.hpp)

define_pd_global(bool, DontYieldALot,            false);

// Set default stack sizes < 2MB so as to prevent stacks from getting
// large-page aligned and backed by THPs on systems where 2MB is the
// default huge page size. For non-JavaThreads, glibc may add an additional
// guard page to the total stack size, so to keep the default sizes same
// for all the following flags, we set them to 2 pages less than 2MB. On
// systems where 2MB is the default large page size, 4KB is most commonly
// the regular page size.
define_pd_global(intx, ThreadStackSize,          2040); // 0 => use system default
define_pd_global(intx, VMThreadStackSize,        2040);

define_pd_global(intx, CompilerThreadStackSize,  2040);

define_pd_global(uintx,JVMInvokeMethodSlack,     8192);

// Used on 64 bit platforms for UseCompressedOops base address
define_pd_global(uintx,HeapBaseMinAddress,       2*G);

class Thread;
extern __thread Thread *aarch64_currentThread;

#endif
