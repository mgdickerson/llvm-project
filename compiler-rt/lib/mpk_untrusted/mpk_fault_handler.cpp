#include "mpk_fault_handler.h"
#include "alloc_site_handler.h"
#include "mpk.h"
#include "mpk_common.h"

uint32_t last_pkey = INVALID_PKEY;
unsigned int last_access_rights = PKEY_DISABLE_ACCESS;

void disableMPK(int signum, siginfo_t *si, void *arg);

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
  __sanitizer::Report(
      "INFO : Got Allocation Site (%d) for address: %p with pkey: %d or %d.\n",
      handler->getAllocSite((rust_ptr)ptr).id(), ptr, pkey);

  // Logic for segfault handling separated out for
  // easier switching between implementation strategies.
  disableMPK(sig, si, arg);
}

/// Get the PKRU pointer from ucontext
uint32_t *get_pkru_pointer(void *arg) {
  ucontext_t *uctxt = (ucontext_t *)arg;
  fpregset_t fpregset = uctxt->uc_mcontext.fpregs;
  char *fpregs = (char *)fpregset;
  int pkru_offset = __mpk_untrusted::pkru_xstate_offset();
  return (uint32_t *)(&fpregs[pkru_offset]);
}

void disableThreadMPK(void *arg, uint32_t pkey) {
  auto pkru_ptr = get_pkru_pointer(arg);

  last_pkey = pkey;
  last_access_rights = __mpk_untrusted::pkey_get(pkru_ptr, pkey);
  __mpk_untrusted::pkey_set(pkru_ptr, pkey, PKEY_ENABLE_ACCESS);
  
  // *(uint64_t *)pkru_ptr = 0x00000000;
  __sanitizer::Report("INFO : Pkey has been set to ENABLE_ACCESS to enable instruction access.\n");
}

void enableThreadMPK(void *arg, uint32_t pkey) {
  auto pkru_ptr = get_pkru_pointer(arg);
  __mpk_untrusted::pkey_set(pkru_ptr, last_pkey, last_access_rights);
  last_pkey = INVALID_PKEY;
  last_access_rights = PKEY_ENABLE_ACCESS;
  return;
}

void disableMPK(int signum, siginfo_t *si, void *arg) {
  #if PAGE_MPK
    // TODO
  #else
    disableThreadMPK(arg, si->si_pkey);
  #endif
}
