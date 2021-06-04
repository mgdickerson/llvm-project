#ifndef MPK_COMMON_H
#define MPK_COMMON_H

#include "sanitizer_common/sanitizer_common.h"
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstring>

// MPK Runtime mode can be set with either of the two following flags,
// PAGE_MPK and SINGLE_STEP_MPK. If neither are defined, default is 
// set to SINGLE_STEP_MPK.
#if !defined(PAGE_MPK) && !defined(SINGLE_STEP_MPK)
  #define SINGLE_STEP_MPK
#endif

// Flag for controlling optional Stats tracking
#ifdef MPK_STATS
#include <atomic>

// Pointer to the global array tracking number of faults per allocation site
extern std::atomic<uint64_t> *AllocSiteUseCounter;
extern std::atomic<uint64_t> allocHookCalls;
extern std::atomic<uint64_t> reallocHookCalls;
extern std::atomic<uint64_t> deallocHookCalls;
extern std::atomic<uint64_t> AllocSiteCount;
#endif

#ifdef MPK_ENABLE_LOGGING
#define REPORT(...) __sanitizer::Report(__VA_ARGS__)
#else
#define REPORT(...)                                                            \
  do {                                                                         \
  } while (0)
#endif

// SINGLE_REPORT functions as the macro above but is intended
// for one off testing when something specific is being debugged
// rather than a general logging macro. Unlike the `REPORT` macro
// this one is not controlled by an `#ifdef` and thus should always
// be removed after usage (or replaced with REPORT if logging is
// desired long term).
#define SINGLE_REPORT(...) __sanitizer::Report(__VA_ARGS__)

#endif // MPK_COMMON_H
