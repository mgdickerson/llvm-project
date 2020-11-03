#include "mpk_untrusted.h"
#include "mpk_fault_handler.h"
#include "mpk_formatter.h"
#include "sanitizer_common/sanitizer_common.h"
#include <cstring>

/// Constructor will intercept allocation functions, initialize
/// allocation_site_handler, and finally set up the segMPKHandle fault handler.
static void mpk_untrusted_constructor() {
  // AllocationSiteHandler will be instantiated on first required call, then
  // accessed on each successive call from the runtime inserts, deletes, and
  // getters.

  __sanitizer::Report("INFO : Initializing and replacing segFaultHandler.\n");

  // Set up our fault handler
  static struct sigaction sa;
  static struct sigaction sa_old;
  memset(&sa, 0, sizeof(struct sigaction));
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = segMPKHandle;
  sigaction(SIGSEGV, &sa, &sa_old);

  #if SINGLE_STEP
    // If we are single stepping, we add an additional signal handler.
    static struct sigaction sa_trap;

    sa_trap.sa_flags = SA_SIGINFO;
    sigemptyset(&sa_trap.sa_mask);
    sa_trap.sa_sigaction = stepMPKHandle;
    sigaction(SIGTRAP, &sa_trap, NULL);
  #endif

  // Add final action flushAllocs()
  std::atexit(__mpk_untrusted::flushAllocs);
}

/// __attribute((constructor)) should allow this function to run before main.
static void __attribute__((constructor)) mpk_untrusted() {
  mpk_untrusted_constructor();
}
