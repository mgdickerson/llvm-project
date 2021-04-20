#include "alloc_site_handler.h"

namespace __mpk_untrusted {

std::shared_ptr<AllocSite> AllocSite::AllocErr = nullptr;
std::shared_ptr<AllocSiteHandler> AllocSiteHandler::handle = nullptr;

std::once_flag ErrorAllocFlag;
std::once_flag StatsInitFlag;
std::once_flag AllocHandlerInitFlag;

void AllocSite::initError() {
  AllocErr = std::shared_ptr<AllocSite>(new AllocSite());
}

/// Returns a shared pointer to the Error AllocSite.
std::shared_ptr<AllocSite> AllocSite::error() {
  std::call_once(ErrorAllocFlag, initError);
  return AllocErr;
}

void AllocSiteHandler::init() {
  handle = std::shared_ptr<AllocSiteHandler>(new AllocSiteHandler());
  mpk_untrusted_constructor();
}

std::shared_ptr<AllocSiteHandler> AllocSiteHandler::getOrInit() {
  std::call_once(AllocHandlerInitFlag, init);
  return handle;
}

} // namespace __mpk_untrusted

extern "C" {
void allocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
  auto site = std::make_shared<__mpk_untrusted::AllocSite>(ptr, size, uniqueID);
  auto handler = __mpk_untrusted::AllocSiteHandler::getOrInit();
  handler->insertAllocSite(ptr, site);
  //REPORT("INFO : AllocSiteHook for address: %p ID: %d.\n", ptr, uniqueID);

#ifdef MPK_STATS
  if (AllocSiteCount != 0)
    allocHookCalls++;
#endif
}

/// reallocHook will remove the previous mapping from oldPtr -> oldAllocSite,
/// and replace it with a mapping from newPtr -> newAllocSite<oldAllocSite>,
/// where the oldAllocSite is added as part of the set of associated allocations
/// for the new mapping.
void reallocHook(rust_ptr newPtr, int64_t newSize, rust_ptr oldPtr,
                 int64_t oldSize, int64_t uniqueID) {
  // Get the AllocSiteHandler and the old AllocSite for the associated oldPtr.
  auto handler = __mpk_untrusted::AllocSiteHandler::getOrInit();
  auto assocSite = handler->getAllocSite(oldPtr);

  // Get the previously associated set from the site being re-allocated and
  // add the previous site to the associated set.
  auto assocSet = assocSite->getAssociatedSet();
  assocSet.insert(assocSite);

  // Remove previous Allocation Site from the mapping.
  handler->removeAllocSite(oldPtr);

  // Create new Allocation Site for given pointer, adding the previous
  // Allocation Site and its associated set to the new AllocSite's associated
  // set.
  auto site = std::make_shared<__mpk_untrusted::AllocSite>(
      newPtr, newSize, uniqueID, 0, assocSet);
  handler->insertAllocSite(newPtr, site);
  //REPORT("INFO : ReallocSiteHook for oldptr: %p, newptr: %p, ID: %d.\n", oldPtr,
  //       newPtr, uniqueID);

#ifdef MPK_STATS
  if (AllocSiteCount != 0)
    reallocHookCalls++;
#endif
}

void deallocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
  auto handler = __mpk_untrusted::AllocSiteHandler::getOrInit();
  handler->removeAllocSite(ptr);
  //REPORT("INFO : DeallocSiteHook for address: %p ID: %d.\n", ptr, uniqueID);

#ifdef MPK_STATS
  if (AllocSiteCount != 0)
    deallocHookCalls++;
#endif
}
}
