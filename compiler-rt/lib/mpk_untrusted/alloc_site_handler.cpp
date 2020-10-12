#include "alloc_site_handler.h"

void allocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
    AllocSite site = AllocSite(ptr, size, uniqueID);
    
    auto handler = AllocSiteHandler::init();
    (*handler)->insertAllocSite(ptr, site);
}

void reallocHook(rust_ptr newPtr, int64_t newSize, rust_ptr oldPtr, int64_t oldSize, int64_t uniqueID) {
    // TODO : This part gets a little tricky, should double check what we want our expected behavior to be here.
}

void deallocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
    auto handler = AllocSiteHandler::init();
    (*handler)->removeAllocSite(ptr);
}