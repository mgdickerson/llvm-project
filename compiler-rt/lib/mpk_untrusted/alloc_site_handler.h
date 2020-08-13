#include <stddef.h>
#include <map>

// TODO : Question: Can we assume that threaded requests for allocation will not overlap? Or will 
// I need to make locks for inserting and retrieving allocations from AllocSiteHandler?
class AllocSiteHandler {
    private:
        // Mapping from memory location pointer to AllocationSite
        std::map<uintptr_t, void*> allocation_map;
        void* ptr;
    public:
        AllocSiteHandler (void*);
        void track_alloc(void* ptr, size_t size, size_t align);
        void untrack_alloc(void* ptr, size_t size, size_t align);
        void track_realloc(void* old_ptr, size_t old_size, void* new_ptr, size_t new_size, size_t align);
        void allocHandlerHook(string funcName);
};

AllocSiteHandler GlobalHandler = AllocSiteHandler(nullptr);