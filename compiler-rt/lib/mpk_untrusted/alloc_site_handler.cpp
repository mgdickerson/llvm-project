#include "alloc_site_handler.h"

namespace __mpk_untrusted {

std::shared_ptr<StatsTracker> StatsTracker::handle = nullptr;
std::shared_ptr<AllocSite> AllocSite::AllocErr = nullptr;
std::shared_ptr<AllocSiteHandler> AllocSiteHandler::handle = nullptr;

} // namespace __mpk_untrusted

extern "C" {
void allocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
  auto site = std::shared_ptr<AllocSite>(new AllocSite(ptr, size, uniqueID));
  auto handler = AllocSiteHandler::init();
  handler->insertAllocSite(ptr, site);
  __sanitizer::Report("INFO : AllocSiteHook for address: %p ID: %d.\n", ptr,
                      uniqueID);
  
  auto stats = StatsTracker::init();
  stats->allocHookCalls++;
  stats->AllocSitesFound.insert(site);
}

/// reallocHook will remove the previous mapping from oldPtr -> oldAllocSite,
/// and replace it with a mapping from newPtr -> newAllocSite<oldAllocSite>,
/// where the oldAllocSite is added as part of the set of associated allocations
/// for the new mapping.
void reallocHook(rust_ptr newPtr, int64_t newSize, rust_ptr oldPtr,
                 int64_t oldSize, int64_t uniqueID) {
  // Get the AllocSiteHandler and the old AllocSite for the associated oldPtr.
  auto handler = AllocSiteHandler::init();
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
  auto site = std::shared_ptr<AllocSite>(
      new AllocSite(newPtr, newSize, uniqueID, assocSet));
  handler->insertAllocSite(newPtr, site);
  __sanitizer::Report(
      "INFO : ReallocSiteHook for oldptr: %p, newptr: %p, ID: %d.\n", oldPtr,
      newPtr, uniqueID);

  auto stats = StatsTracker::init();
  stats->reallocHookCalls++;
  stats->ReallocSitesFound.insert(site);
}

void deallocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
  auto handler = __mpk_untrusted::AllocSiteHandler::init();
  handler->removeAllocSite(ptr);
  __sanitizer::Report("INFO : DeallocSiteHook for address: %p ID: %d.\n", ptr,
                      uniqueID);
  
  auto stats = StatsTracker::init();
  stats->deallocHookCalls++;
}
}

