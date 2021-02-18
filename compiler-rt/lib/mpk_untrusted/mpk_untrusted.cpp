#include "mpk_untrusted.h"

#ifdef MPK_STATS
std::atomic<uint64_t>* AllocSiteUseCounter(nullptr);
std::atomic<uint64_t> allocHookCalls(0);
std::atomic<uint64_t> reallocHookCalls(0);
std::atomic<uint64_t> deallocHookCalls(0);
uint64_t AllocSiteCount = 0;
#endif

extern "C" {

/// Constructor will set up the segMPKHandle fault handler, and additionally
/// the stepMPKHandle when testing single stepping.
void mpk_untrusted_constructor() {
#ifdef MPK_STATS
  // If MPK_STATS is defined, grab the total allocation sites value and initialize dynamic array.
  // std::atomic should be 0 initialized according to docs.
  AllocSiteUseCounter = new std::atomic<uint64_t>[AllocSiteTotal]();
  AllocSiteCount = AllocSiteTotal;
#endif

  REPORT("INFO : Initializing and replacing segFaultHandler.\n");

  // Set up our fault handler
  static struct sigaction sa;
  static struct sigaction sa_old;
  memset(&sa, 0, sizeof(struct sigaction));
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = __mpk_untrusted::segMPKHandle;
  sigaction(SIGSEGV, &sa, &sa_old);

#if SINGLE_STEP
  // If we are single stepping, we add an additional signal handler.
  static struct sigaction sa_trap;

  sa_trap.sa_flags = SA_SIGINFO;
  sigemptyset(&sa_trap.sa_mask);
  sa_trap.sa_sigaction = __mpk_untrusted::stepMPKHandle;
  sigaction(SIGTRAP, &sa_trap, NULL);
#endif

  // Add final action flushAllocs() to export faulting allocations
  // to a JSON file.
  std::atexit(__mpk_untrusted::flushAllocs);
}
}
