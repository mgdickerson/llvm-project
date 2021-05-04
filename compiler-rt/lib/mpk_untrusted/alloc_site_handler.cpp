#include "alloc_site_handler.h"

namespace __mpk_untrusted {
bool destructorRan = false;

AllocSiteHandler* AllocSiteHandle = nullptr;

// std::shared_ptr<AllocSiteHandler> AllocSiteHandler::handle = nullptr;

std::once_flag ErrorAllocFlag;
std::once_flag StatsInitFlag;
std::once_flag AllocHandlerInitFlag;

// TODO: this can be constexpr
/// Returns a shared pointer to the Error AllocSite.
AllocSite AllocSite::error() { return AllocSite(); }

void AllocSiteHandler::init() {
  // handle = std::shared_ptr<AllocSiteHandler>(new AllocSiteHandler());
  AllocSiteHandle = new AllocSiteHandler();
  mpk_untrusted_constructor();
}

AllocSiteHandler* AllocSiteHandler::getOrInit() {
  std::call_once(AllocHandlerInitFlag, init);
  // return handle;
  if (!AllocSiteHandle) 
      REPORT("AllocSiteHandle is null!\n");
  return AllocSiteHandle;
}

} // namespace __mpk_untrusted

extern "C" {
void allocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
  __mpk_untrusted::AllocSite site(ptr, size, uniqueID);
  auto handler = __mpk_untrusted::AllocSiteHandler::getOrInit();
  handler->insertAllocSite(ptr, site);
  // REPORT("INFO : AllocSiteHook for address: %p ID: %d.\n", ptr, uniqueID);

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

  if (!assocSite.isValid()) {
    // Returned ErrorAlloc, which should not be part of the realloc chain.
    __mpk_untrusted::AllocSite site(newPtr, newSize, uniqueID);
    handler->insertAllocSite(newPtr, site);
    return;
  }

  // Get the previously associated set from the site being re-allocated and
  // add the previous site to the associated set.
  auto assocSet = assocSite.getAssociatedSet();
  assocSet.insert(assocSite);

  // Remove previous Allocation Site from the mapping.
  handler->removeAllocSite(oldPtr);

  // Create new Allocation Site for given pointer, adding the previous
  // Allocation Site and its associated set to the new AllocSite's associated
  // set.
  __mpk_untrusted::AllocSite site(newPtr, newSize, uniqueID, 0, assocSet);
  handler->insertAllocSite(newPtr, site);
  // REPORT("INFO : ReallocSiteHook for oldptr: %p, newptr: %p, ID: %d.\n",
  // oldPtr,
  //       newPtr, uniqueID);

#ifdef MPK_STATS
  if (AllocSiteCount != 0)
    reallocHookCalls++;
#endif
}

void deallocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
  auto handler = __mpk_untrusted::AllocSiteHandler::getOrInit();
  if (__mpk_untrusted::destructorRan) {
    REPORT("ERROR : deallocHook has been called after AllocSiteHandler has been destroyed.\n");
    return;
  }
  //if (!handler) {
    //// deallocHook has been called after global AllocSiteHandler has been
    //// destroyed.
    //REPORT("ERROR : deallocHook has been called after AllocSiteHandler has "
           //"been destroyed.\n");
    //return;
  //}

  handler->removeAllocSite(ptr);
  // REPORT("INFO : DeallocSiteHook for address: %p ID: %d.\n", ptr, uniqueID);

#ifdef MPK_STATS
  if (AllocSiteCount != 0)
    deallocHookCalls++;
#endif
}
} // end extern "C"
