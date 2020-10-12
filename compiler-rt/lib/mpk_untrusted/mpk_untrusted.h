#include "alloc_site_handler.h"
#include "dyn_interrupt.h"
#include "mpk_fault_handler.h"
#include "stddef.h"
#include "signal.h"
#include "stdio.h"
#include <cstring>

/// Constructor will intercept allocation functions, initialize allocation_site_handler,
/// and finally set up the segMPKHandle fault handler.
static void mpk_untrusted_constructor() {
    // AllocationSiteHandler will be instantiated on first required call, then accessed
    // on each successive call from the runtime inserts, deletes, and getters.

    // Set up our fault handler
    static struct sigaction sa;
    static struct sigaction sa_old;
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segMPKHandle;
    sigaction(SIGSEGV, &sa, &sa_old);
}

/// __attribute((constructor)) should allow this function to run before main.
static void __attribute__((constructor)) mpk_untrusted() {
    mpk_untrusted_constructor();
}