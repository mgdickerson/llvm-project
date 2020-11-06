#ifndef ALLOCSITEHANDLER_H
#define ALLOCSITEHANDLER_H

#include "sanitizer_common/sanitizer_common.h"

#include <cassert>
#include <map>
#include <memory>
#include <mutex>
#include <set>

typedef int8_t *rust_ptr;

namespace __mpk_untrusted {

class AllocSite {
private:
  rust_ptr ptr;
  int64_t size;
  int64_t uniqueID;
  uint32_t pkey;
  AllocSite() : ptr(nullptr), size(-1), uniqueID(-1), pkey(0) {}

public:
  AllocSite(rust_ptr ptr, int64_t size, int64_t uniqueID)
      : ptr{ptr}, size{size}, uniqueID{uniqueID}, pkey{0} {
    assert(ptr != nullptr);
    assert(size > 0);
    assert(uniqueID >= 0);
  }

  static AllocSite error() { return AllocSite(); }

  bool containsPtr(rust_ptr ptrCmp) {
    // TODO : Note, might be important to cast pointers to uintptr_t type for
    // arithmetic comparisons if it behaves incorrectly.
    return (ptr <= ptrCmp) && (ptrCmp < (ptr + size));
  }

  int64_t id() const { return uniqueID; }

  rust_ptr getPtr() { return ptr; }

  bool isValid() { return (ptr != nullptr) && (size > 0) && (uniqueID >= 0); }

  void addPkey(uint32_t faultPkey) { pkey = faultPkey; }

  uint32_t getPkey() { return pkey; }

  bool operator<(const AllocSite &ac) const { return uniqueID < ac.id(); }
};

class AllocSiteHandler {
private:
  // Singleton AllocSiteHandler pointer
  static std::shared_ptr<AllocSiteHandler> handle;
  // Mapping from memory location pointer to AllocationSite
  std::map<rust_ptr, AllocSite> allocation_map;
  // Set of faulting AllocationSites
  std::set<AllocSite> fault_set;
  // Thread safety mutex
  std::mutex mx;
  AllocSiteHandler() = default;

public:
  ~AllocSiteHandler() {}

  static std::shared_ptr<AllocSiteHandler> init() {
    if (!handle) {
      handle = std::shared_ptr<AllocSiteHandler>(new AllocSiteHandler());
    }

    return handle;
  }

  bool empty() { return allocation_map.empty(); }

  void insertAllocSite(rust_ptr ptr, AllocSite site) {
    // First, obtain the mutex lock to ensure safe addition of item to map.
    const std::lock_guard<std::mutex> lock(mx);

    // Insert AllocationSite for given ptr.
    allocation_map.insert(std::pair<rust_ptr, AllocSite>(ptr, site));

    // lock falls out of scope and releases mutex.
  }

  void removeAllocSite(rust_ptr ptr) {
    // Obtain mutex lock.
    const std::lock_guard<std::mutex> lock(mx);

    // Remove AllocationSite for given ptr.
    allocation_map.erase(ptr);
  }

  AllocSite getAllocSite(rust_ptr ptr) {
    // Obtain mutex lock.
    const std::lock_guard<std::mutex> lock(mx);

    if (allocation_map.empty()) {
      __sanitizer::Report("INFO : Map is empty, returning error.\n");
      return AllocSite::error();
    }

    // Get AllocSite found from given rust_ptr
    auto map_iter = allocation_map.lower_bound(ptr);

    // First check to make sure the iterator is not past the end of the map,
    // otherwise return error.
    if (map_iter != allocation_map.end()) {
      // Found valid iterator, check for exact match first
      if (map_iter->first == ptr) {
        // For an exact match, we can return the found alloction site
        return map_iter->second;
      }

      // If it is not an exact match, we need to check the AllocationSite
      // immediately before found site. Check that map_iter is not the first
      // item, otherwise return error.
      if (map_iter != allocation_map.begin()) {
        --map_iter;
        if (map_iter->second.containsPtr(ptr)) {
          return map_iter->second;
        }
        // If we reach this point, it means the allocation site did not contain
        // this pointer. Return Error.
      }
    }

    __sanitizer::Report("INFO : Returning AllocSite::error()\n");
    return AllocSite::error();
  }

  void addFaultAlloc(rust_ptr ptr, uint32_t pkey) {
    auto alloc = getAllocSite(ptr);
    __sanitizer::Report("INFO : Getting AllocSite : id(%d), ptr(%p)\n",
                        alloc.id(), alloc.getPtr());

    if (!alloc.isValid()) {
      __sanitizer::Report(
          "INFO : AllocSite is not valid, will not add it to Fault Set.\n");
      return;
    }

    alloc.addPkey(pkey);

    fault_set.insert(alloc);
  }

  std::set<AllocSite> &faultingAllocs() { return fault_set; }
};
} // namespace __mpk_untrusted
extern "C" {
__attribute__((visibility("default"))) void
allocHook(rust_ptr ptr, int64_t size, int64_t uniqueID);
__attribute__((visibility("default"))) void
reallocHook(rust_ptr newPtr, int64_t newSize, rust_ptr oldPtr, int64_t oldSize,
            int64_t uniqueID);
__attribute__((visibility("default"))) void
deallocHook(rust_ptr ptr, int64_t size, int64_t uniqueID);
}
#endif
