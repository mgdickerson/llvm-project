#include "mpk_fault_handler.h"

void disableMPK(int signum, siginfo_t *si, void *arg);

void segMPKHandle(int sig, siginfo_t *si, void *arg) {
  if (si->si_code != SEGV_PKUERR) {
    __sanitizer::Report("INFO : SegFault other than SEGV_PKUERR, handling with default handler.");
    // SignalHandler was invoked from an error other than MPK violation.
    // Perform default action instead and return.
    signal(sig, SIG_DFL);
    raise(sig);
    return;
  }

  // A pkey pointer in signal info? For now, print this output as part
  // of the information and see what information it gives us.
  uint32_t *si_pkey_ptr = (uint32_t *)(((uint8_t *)si) + si_pkey_offset);
  uint64_t sig_pkey = *si_pkey_ptr;

  // Obtains pointer causing fault
  void *ptr = si->si_addr;
  uint32_t pkey = si->si_pkey;
  
  // Get Alloc Site information from the handler.
  auto handler = AllocSiteHandler::init();
  __sanitizer::Report("INFO : Got Allocation Site (%d) for address: %p with pkey: %d or %d.\n", (*handler)->getAllocSite((rust_ptr)ptr), ptr, sig_pkey, pkey);

  // Logic for segfault handling separated out for 
  // easier switching between implementation strategies.
  disableMPK(sig, si, arg);
}

/// Get the PKRU pointer from ucontext
uint32_t *get_pkru_pointer(void* arg) {
  ucontext_t *uctxt = (ucontext_t *)arg;
  fpregset_t fpregset = uctxt->uc_mcontext.fpregs;
  char *fpregs = (char *)fpregset;
  int pkru_offset = __mpk_untrusted::pkru_xstate_offset();
  return (uint32_t *)(&fpregs[pkru_offset]);
}

void disableThreadMPK(void *arg) {
  auto pkru_ptr = get_pkru_pointer(arg);

  // TODO : For now until I can confirm that the pkey from *si is the actual pkey
  // we will give permission by just complete overwriting the register.
  uint64_t PKRU_STATE = *(uint64_t *)pkru_ptr;
  *(uint64_t *)pkru_ptr = 0x00000000;
  __sanitizer::Report("INFO : PKRU register set to 0 to enable instruction access.\n");
}

void disableMPK(int signum, siginfo_t *si, void *arg) {
  #if PAGE_MPK
    // TODO
  #else
    disableThreadMPK(arg);
  #endif
}