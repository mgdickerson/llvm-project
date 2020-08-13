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
    // Start with intercepting allocation functions.
    if (!intercept_functions()) {
        // One of the intercepts has failed, crash out with error messages printed.
        std::cout << "Failed to intercept one or more alloction functions!" << std::endl;
        return;
    }

    // Set up AllocationSiteHandler
    // TODO

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