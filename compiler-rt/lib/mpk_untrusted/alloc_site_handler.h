#ifndef ALLOCSITEHANDLER_H
#define ALLOCSITEHANDLER_H

#include <assert.h>
#include <stddef.h>
#include <map>
#include <memory>
#include <mutex>

typedef int8_t* rust_ptr;

class AllocSite {
    private:
        rust_ptr ptr;
        int64_t size;
        int64_t uniqueID;
        AllocSite() {
            ptr = nullptr;
            size = -1;
            uniqueID = -1;
        }
    public:
        AllocSite(rust_ptr ptr, int64_t size, int64_t uniqueID) : ptr{ptr}, size{size}, uniqueID{uniqueID} {
            assert(ptr != nullptr);
            assert(size > 0);
            assert(uniqueID >= 0);
        }

        static AllocSite error() {
            return AllocSite();
        }
        
        // TODO : Note, might be important to cast pointers to uintptr_t type for arithmetic comparisons if it behaves incorrectly.
        bool containsPtr(rust_ptr ptrCmp) {
            return (ptr <= ptrCmp) && (ptrCmp < (ptr + size));
        }

        int64_t id() {
            return uniqueID;
        }

        bool isValid() {
            return (ptr != nullptr) && (size > 0) && (uniqueID >= 0);
        }
};

class AllocSiteHandler {
    private:
        // Singleton AllocSiteHandler pointer
        static AllocSiteHandler* handle;
        // Mapping from memory location pointer to AllocationSite
        std::map<rust_ptr, AllocSite> allocation_map;
        std::mutex mx;
        AllocSiteHandler() {
            std::map<rust_ptr, AllocSite> allocation_map;
            std::mutex mx;
        }
        ~AllocSiteHandler();
    public:
        static std::shared_ptr<AllocSiteHandler*> init() {
            if (!handle) {
                handle = new AllocSiteHandler();
            }

            return std::make_shared<AllocSiteHandler*>(handle);
        }

        bool empty() {
            return allocation_map.empty();
        }
        
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

            // Get AllocSite found from given rust_ptr
            auto map_iter = allocation_map.lower_bound(ptr);

            // First check to make sure the iterator is not past the end of the map, otherwise return error.
            if (map_iter != allocation_map.end()) {
                // Found valid iterator, check for exact match first
                if (map_iter->first == ptr) {
                    // For an exact match, we can return the found alloction site
                    return map_iter->second;
                }

                // If it is not an exact match, we need to check the AllocationSite immediately before found site.
                // Check that map_iter is not the first item, otherwise return error.
                if (map_iter != allocation_map.begin()) {
                    --map_iter;
                    if (map_iter->second.containsPtr(ptr)) {
                        return map_iter->second;
                    }
                    // If we reach this point, it means the allocation site did not contain this pointer. Return Error.
                }
            }

            return AllocSite::error();
        }
};

void allocHook(rust_ptr ptr, int64_t size, int64_t uniqueID);
void reallocHook(rust_ptr newPtr, int64_t newSize, rust_ptr oldPtr, int64_t oldSize, int64_t uniqueID);
void deallocHook(rust_ptr ptr, int64_t size, int64_t uniqueID);

#endif
