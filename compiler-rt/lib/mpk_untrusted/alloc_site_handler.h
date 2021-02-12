#ifndef ALLOCSITEHANDLER_H
#define ALLOCSITEHANDLER_H

#include "mpk_common.h"
#include "mpk_untrusted.h"
#include "llvm/ADT/Optional.h"

#include <cassert>
#include <map>
#include <memory>
#include <mutex>
#include <set>

typedef int8_t *rust_ptr;

namespace __mpk_untrusted {

class AllocSite {
  typedef std::set<std::shared_ptr<AllocSite>> alloc_set_type;

private:
  static std::shared_ptr<AllocSite> AllocErr;

  rust_ptr ptr;
  int64_t size;
  int64_t uniqueID;
  uint32_t pkey;
  alloc_set_type associatedSet;
  AllocSite() : ptr(nullptr), size(-1), uniqueID(-1), pkey(0) {}

public:
  AllocSite(rust_ptr ptr, int64_t size, int64_t uniqueID, uint32_t pkey = 0,
            alloc_set_type assocSet = alloc_set_type())
      : ptr{ptr}, size{size}, uniqueID{uniqueID}, pkey{pkey}, associatedSet{
                                                                  assocSet} {
    assert(ptr != nullptr);
    assert(size > 0);
    assert(uniqueID >= 0);
  }

  static void initError();

  /// Returns a shared pointer to the Error AllocSite.
  static std::shared_ptr<AllocSite> error();

  // Note : containsPtr contains potentially wrapping arithmetic. If a ptr
  // and the allocations size exceed 0xffffffffffffffff, then any pointer
  // searched for in the valid range will return False, as it cannot satisfy 
  // both requirments in the check.
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

  alloc_set_type getAssociatedSet() { return associatedSet; }

  bool operator<(const AllocSite &ac) const { return uniqueID < ac.id(); }
};

class StatsTracker {
private:
  static std::shared_ptr<StatsTracker> handle;
  StatsTracker() = default;

public:
  uint64_t allocHookCalls;
  uint64_t reallocHookCalls;
  uint64_t deallocHookCalls;
  std::map<std::shared_ptr<AllocSite>, uint64_t> AllocSiteFaultCount;
  std::set<std::shared_ptr<AllocSite>> AllocSitesFound;
  std::set<std::shared_ptr<AllocSite>> ReallocSitesFound;

  static void init();
  static std::shared_ptr<StatsTracker> getOrInit();

  void incFaultCount(std::shared_ptr<AllocSite> alloc) {
    auto it = AllocSiteFaultCount.find(alloc);
    if (it != AllocSiteFaultCount.end()) {
      it->second++;
    } else {
      AllocSiteFaultCount.insert(
          std::pair<std::shared_ptr<AllocSite>, uint64_t>(alloc, 1));
    }
  }
};

struct PKeyInfo {
public:
  uint32_t pkey;
  unsigned int access_rights;
  PKeyInfo(uint32_t pkey, unsigned int access_rights)
      : pkey(pkey), access_rights(access_rights) {}
};

class AllocSiteHandler {
private:
  // Singleton AllocSiteHandler pointer
  static std::shared_ptr<AllocSiteHandler> handle;
  // Mapping from memory location pointer to AllocationSite
  std::map<rust_ptr, std::shared_ptr<AllocSite>> allocation_map;
  // Set of faulting AllocationSites
  std::set<AllocSite> fault_set;
  // allocation_map mutex
  std::mutex alloc_map_mx;
  // Mapping of thread-id to saved pkey
  std::map<pid_t, PKeyInfo> pkey_by_pid_map;
  // pkey_by_pid_map mutex
  std::mutex pkey_pid_map_px;
  AllocSiteHandler() = default;

public:
  ~AllocSiteHandler() {}

  static void init();
  static std::shared_ptr<AllocSiteHandler> getOrInit();

  bool empty() { return allocation_map.empty(); }

  void insertAllocSite(rust_ptr ptr, std::shared_ptr<AllocSite> site) {
    // First, obtain the mutex lock to ensure safe addition of item to map.
    const std::lock_guard<std::mutex> alloc_map_guard(alloc_map_mx);

    // Insert AllocationSite for given ptr.
    allocation_map.insert(
        std::pair<rust_ptr, std::shared_ptr<AllocSite>>(ptr, site));
  }

  void removeAllocSite(rust_ptr ptr) {
    // Obtain mutex lock.
    const std::lock_guard<std::mutex> alloc_map_guard(alloc_map_mx);

    // Remove AllocationSite for given ptr.
    allocation_map.erase(ptr);
  }

  std::shared_ptr<AllocSite> getAllocSite(rust_ptr ptr) {
    // Obtain mutex lock.
    const std::lock_guard<std::mutex> alloc_map_guard(alloc_map_mx);

    if (allocation_map.empty()) {
      REPORT("INFO : Map is empty, returning error.\n");
      return AllocSite::error();
    }

    // Get AllocSite found from given rust_ptr
    auto map_iter = allocation_map.lower_bound(ptr);

    // First check to see if we found an exact match.
    if (map_iter != allocation_map.end()) {
      // Found valid iterator, check for exact match first
      if (map_iter->first == ptr) {
        // For an exact match, we can return the found allocation site
        return map_iter->second;
      }
    }

    // If it was not an exact match (or iterator was at map.end()), check
    // previous node to see if it is contained within valid range.
    if (map_iter != allocation_map.begin())
      --map_iter;

    if (map_iter->second->containsPtr(ptr))
      return map_iter->second;

    // If pointer was not an exact match, was not the beginning node,
    // and was not the node before the returned result of lower_bound,
    // then item is not contained within map. Return error node.
    REPORT("INFO : Returning AllocSite::error()\n");
    return AllocSite::error();
  }

  void addFaultAlloc(rust_ptr ptr, uint32_t pkey) {
    auto alloc = getAllocSite(ptr);
    REPORT("INFO : Getting AllocSite : id(%d), ptr(%p)\n", alloc->id(),
           alloc->getPtr());

    if (!alloc->isValid()) {
      REPORT("INFO : AllocSite is not valid, will not add it to Fault Set.\n");
      return;
    }

    alloc->addPkey(pkey);

    fault_set.insert(*alloc);

    // Increment the count of the allocation faulting
    auto stats = StatsTracker::getOrInit();
    stats->incFaultCount(alloc);

    for (auto assoc : alloc->getAssociatedSet()) {
      assoc->addPkey(pkey);
      fault_set.insert(*assoc);
      stats->incFaultCount(assoc);
    }
  }

  /// For single instruction stepping, this function will store a given PKey's
  /// permissions for a given thread-id
  void storePKeyInfo(pid_t threadID, PKeyInfo pkey) {
    // Obtain map key
    const std::lock_guard<std::mutex> pkey_map_guard(pkey_pid_map_px);

    pkey_by_pid_map.insert(std::pair<pid_t, PKeyInfo>(threadID, pkey));
  }

  /// For single instruction stepping, this will pop the associated PKey
  /// information for a given thread-id from the pkey_by_pid_map
  llvm::Optional<PKeyInfo> popPendingPKeyInfo(pid_t threadID) {
    // Obtain map key
    const std::lock_guard<std::mutex> pkey_map_guard(pkey_pid_map_px);

    auto iter = pkey_by_pid_map.find(threadID);
    // If PID does not contain key in map, return None.
    if (iter == pkey_by_pid_map.end())
      return llvm::None;

    auto ret_val = iter->second;
    pkey_by_pid_map.erase(threadID);
    return ret_val;
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
