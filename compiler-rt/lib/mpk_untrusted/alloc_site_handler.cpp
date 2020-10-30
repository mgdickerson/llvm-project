#include "alloc_site_handler.h"
#include "sanitizer_common/sanitizer_common.h"

namespace __mpk_untrusted {

std::shared_ptr<AllocSiteHandler> AllocSiteHandler::handle = nullptr;

void allocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
  AllocSite site(ptr, size, uniqueID);
  auto handler = AllocSiteHandler::init();
  handler->insertAllocSite(ptr, site);
  __sanitizer::Report("INFO : AllocSiteHook for address: %p ID: %d.\n", ptr,
                      uniqueID);
}

// TODO : For future versions, we want to union the previous AllocSite from old
// ptr, with the new ptr.
void reallocHook(rust_ptr newPtr, int64_t newSize, rust_ptr oldPtr,
                 int64_t oldSize, int64_t uniqueID) {
  // TODO : For now we are simply going to remove the old one and input the new
  // one.
  auto handler = AllocSiteHandler::init();
  handler->removeAllocSite(oldPtr);
  AllocSite site(newPtr, newSize, uniqueID);
  handler->insertAllocSite(newPtr, site);
  __sanitizer::Report(
      "INFO : ReallocSiteHook for oldptr: %p, newptr: %p, ID: %d.\n", oldPtr,
      newPtr, uniqueID);
}

void deallocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
  auto handler = AllocSiteHandler::init();
  handler->removeAllocSite(ptr);
  __sanitizer::Report("INFO : DeallocSiteHook for address: %p ID: %d.\n", ptr,
                      uniqueID);
}

} // namespace __mpk_untrusted
