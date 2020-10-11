#include <stddef.h>
#include <map>

// TODO : Question: Can we assume that threaded requests for allocation will not overlap? Or will 
// I need to make locks for inserting and retrieving allocations from AllocSiteHandler?

// TODO : Answer for above, yes. We will need to write a simple spin lock.

class AllocSite {
    private:
        int8_t* ptr;
        int64_t size;
        int64_t uniqueID;
    public:
        AllocSite(int8_t* ptr, int64_t size, int64_t uniqueID) : ptr(ptr), size(size), uniqueID(uniqueID) {}
        
        bool containsPtr(int8_t* ptrCmp) {
            return (ptr <= ptrCmp) && (ptrCmp < (ptr + size));
        }

        int64_t uniqeID() {
            return uniqeID;
        }
}

class AllocSiteHandler {
    private:
        // Mapping from memory location pointer to AllocationSite
        std::map<int8_t*, AllocSite> allocation_map;
    public:
        AllocSiteHandler();
        void insertAllocSite(int8_t* ptr, AllocSite site);
        void removeAllocSite(int8_t* ptr);
        AllocSite getAllocSite(int8_t* ptr);
};

static AllocSiteHandler GlobalHandler = AllocSiteHandler(nullptr);

void allocHook(int8_t* ptr, int64_t size, int64_t uniqueID);
void reallocHook(int8_t* newPtr, int64_t newSize, int8_t* oldPtr, int64_t oldSize, int64_t uniqueID);
void deallocHook(int8_t* ptr, int64_t size, int64_t uniqueID);