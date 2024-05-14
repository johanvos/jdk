#ifndef OS_ANDROID_GLOBALS_ANDROID_HPP
#define OS_ANDROID_GLOBALS_ANDROID_HPP

//
// Declare Linux specific flags. They are not available on other platforms.
//
#define RUNTIME_OS_FLAGS(develop,                                       \
                         develop_pd,                                    \
                         product,                                       \
                         product_pd,                                    \
                         range,                                         \
                         constraint)                                    \
                                                                        \
  product(bool, UseOprofile, false,                                     \
        "enable support for Oprofile profiler")                         \
                                                                        \
  /*  NB: The default value of UseLinuxPosixThreadCPUClocks may be   */ \
  /* overridden in Arguments::parse_each_vm_init_arg.                */ \
  product(bool, UseLinuxPosixThreadCPUClocks, true,                     \
          "enable fast Linux Posix clocks where available")             \
                                                                        \
  product(bool, UseTransparentHugePages, false,                         \
          "Use MADV_HUGEPAGE for large pages")                          \
                                                                        \
  product(bool, LoadExecStackDllInVMThread, true,                       \
          "Load DLLs with executable-stack attribute in the VM Thread") \
                                                                        \
  product(bool, UseContainerSupport, true,                              \
          "Enable detection and runtime container configuration support") \
                                                                        \
  product(bool, AdjustStackSizeForTLS, false,                           \
          "Increase the thread stack size to include space for glibc "  \
          "static thread-local storage (TLS) if true")                  \
                                                                        \
  product(bool, DumpPrivateMappingsInCore, true, DIAGNOSTIC,            \
          "If true, sets bit 2 of /proc/PID/coredump_filter, thus "     \
          "resulting in file-backed private mappings of the process to "\
          "be dumped into the corefile.")                               \
                                                                        \
  product(bool, DumpSharedMappingsInCore, true, DIAGNOSTIC,             \
          "If true, sets bit 3 of /proc/PID/coredump_filter, thus "     \
          "resulting in file-backed shared mappings of the process to " \
          "be dumped into the corefile.")                               \
                                                                        \
  product(bool, UseCpuAllocPath, false, DIAGNOSTIC,                     \
          "Use CPU_ALLOC code path in os::active_processor_count ")     \
                                                                        \
  product(bool, DumpPerfMapAtExit, false, DIAGNOSTIC,                   \
          "Write map file for Linux perf tool at exit")                 \
                                                                        \
  product(intx, TimerSlack, -1, EXPERIMENTAL,                           \
          "Overrides the timer slack value to the given number of "     \
          "nanoseconds. Lower value provides more accurate "            \
          "high-precision timers, at the expense of (possibly) worse "  \
          "power efficiency. In current Linux, 0 means using the "      \
          "system-wide default, which would disable the override, but " \
          "VM would still print the current timer slack values. Use -1 "\
          "to disable both the override and the printouts."             \
          "See prctl(PR_SET_TIMERSLACK) for more info.")                \
                                                                        \
  product(bool, THPStackMitigation, true, DIAGNOSTIC,                   \
          "If THPs are unconditionally enabled on the system (mode "    \
          "\"always\"), the JVM will prevent THP from forming in "      \
          "thread stacks. When disabled, the absence of this mitigation"\
          "allows THPs to form in thread stacks.")                      \
                                                                        \
  develop(bool, DelayThreadStartALot, false,                            \
          "Artificially delay thread starts randomly for testing.")     \
                                                                        \
  product(bool, UseMadvPopulateWrite, true, DIAGNOSTIC,                 \
          "Use MADV_POPULATE_WRITE in os::pd_pretouch_memory.")         \
                                                                        \

// end of RUNTIME_OS_FLAGS

//
// Defines Linux-specific default values. The flags are available on all
// platforms, but they may have different default values on other platforms.
//
define_pd_global(size_t, PreTouchParallelChunkSize, 4 * M);
define_pd_global(bool, UseLargePages, false);
define_pd_global(bool, UseLargePagesIndividualAllocation, false);
define_pd_global(bool, UseThreadPriorities, true) ;

#endif // OS_ANDROID_GLOBALS_ANDROID_HPP
