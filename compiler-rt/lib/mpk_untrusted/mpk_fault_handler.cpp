#include "mpk_fault_handler.h"
#include "alloc_site_handler.h"
#include "mpk.h"

#include <sys/mman.h>

const int PAGE_SIZE = 4096;

// Trap Flag
#define TF 0x100

uint32_t last_pkey = INVALID_PKEY;
unsigned int last_access_rights = PKEY_DISABLE_ACCESS;

void disableMPK(siginfo_t *si, void *arg);

void segMPKHandle(int sig, siginfo_t *si, void *arg) {
  if (si->si_code != SEGV_PKUERR) {
    __sanitizer::Report("INFO : SegFault other than SEGV_PKUERR, handling with "
                        "default handler.\n");
    // SignalHandler was invoked from an error other than MPK violation.
    // Perform default action instead and return.
    signal(sig, SIG_DFL);
    raise(sig);
    return;
  }

  // Obtains pointer causing fault
  void *ptr = si->si_addr;

  // Obtains the faulting pkey (in SEGV_PKUERR faults)
  uint32_t pkey = si->si_pkey;

  // Get Alloc Site information from the handler.
  auto handler = __mpk_untrusted::AllocSiteHandler::init();
  handler->addFaultAlloc((rust_ptr)ptr, pkey);
  __sanitizer::Report(
      "INFO : Got Allocation Site (%d) for address: %p with pkey: %d or %d.\n",
      handler->getAllocSite((rust_ptr)ptr)->id(), ptr, pkey);
  disableMPK(si, arg);
}

void disablePageMPK(siginfo_t *si, void *arg) {
  void *page_addr = (void *)((uintptr_t)si->si_addr & ~(PAGE_SIZE - 1));

  __sanitizer::Report("Disabling MPK protection for page(%p).", page_addr);

  pkey_mprotect(page_addr, PAGE_SIZE, PROT_READ | PROT_WRITE, 0);
}

void disableThreadMPK(void *arg, uint32_t pkey) {
  uint32_t *pkru_ptr = __mpk_untrusted::pkru_ptr(arg);

  last_pkey = pkey;
  last_access_rights = __mpk_untrusted::pkey_get(pkru_ptr, pkey);
  __mpk_untrusted::pkey_set(pkru_ptr, pkey, PKEY_ENABLE_ACCESS);

  __sanitizer::Report("INFO : Pkey(%d) has been set to ENABLE_ACCESS to enable "
                      "instruction access.\n",
                      pkey);
}

void enableThreadMPK(void *arg, uint32_t pkey) {
  uint32_t *pkru_ptr = __mpk_untrusted::pkru_ptr(arg);
  __mpk_untrusted::pkey_set(pkru_ptr, last_pkey, last_access_rights);
  __sanitizer::Report("INFO : Pkey(%d) has been reset to %d.\n", last_pkey,
                      last_access_rights);
  last_pkey = INVALID_PKEY;
  last_access_rights = PKEY_ENABLE_ACCESS;
}

void disableMPK(siginfo_t *si, void *arg) {
#if PAGE_MPK
  disablePageMPK(si, arg);
#else
#if SINGLE_STEP
  disableThreadMPK(arg, si->si_pkey);

  // Set trap flag on next instruction
  ucontext_t *uctxt = (ucontext_t *)arg;
  uctxt->uc_mcontext.gregs[REG_EFL] |= TF;
#else
  // TODO : emulateMPK();
#endif
#endif
}

void stepMPKHandle(int sig, siginfo_t *si, void *arg) {
  __sanitizer::Report(
      "Reached signal handler after single instruction step.\n");
  enableThreadMPK(arg, si->si_pkey);

  // Disable trap flag on next instruction
  ucontext_t *uctxt = (ucontext_t *)arg;
  uctxt->uc_mcontext.gregs[REG_EFL] &= ~TF;
}
