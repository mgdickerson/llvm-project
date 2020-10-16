#include "alloc_site_handler.h"

AllocSiteHandler* AllocSiteHandler::handle = nullptr;

void allocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
    AllocSite site = AllocSite(ptr, size, uniqueID);
    
    auto handler = AllocSiteHandler::init();
    (*handler)->insertAllocSite(ptr, site);
}

// TODO : For future versions, we want to union the previous AllocSite from old ptr, with the new ptr.
void reallocHook(rust_ptr newPtr, int64_t newSize, rust_ptr oldPtr, int64_t oldSize, int64_t uniqueID) {
    // TODO : For now we are simply going to remove the old one and input the new one.
    auto handler = AllocSiteHandler::init();
    (*handler)->removeAllocSite(oldPtr);
    AllocSite site = AllocSite(newPtr, newSize, uniqueID);
    (*handler)->insertAllocSite(newPtr, site);
}

void deallocHook(rust_ptr ptr, int64_t size, int64_t uniqueID) {
    auto handler = AllocSiteHandler::init();
    (*handler)->removeAllocSite(ptr);
}
