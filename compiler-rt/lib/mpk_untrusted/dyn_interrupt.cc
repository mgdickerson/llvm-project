#include "dyn_interrupt.h"

/// Assuming standard allocator is being used, the following interceptors should 
/// handle tracking within alloc_site_handler and then call original allocation
/// function.

bool intercept_functions() {
    bool intercept_successful = true;

    if (!INTERCEPT_FUNCTION(__rust_alloc)) {
        intercept_successful = false;
        std::cout << "Failed to intecept __rust_alloc!" << std::endl;
    }

    if (!INTERCEPT_FUNCTION(__rust_dealloc)) {
        intercept_successful = false;
        std::cout << "Failed to intercept __rust_dealloc" << std::endl;
    }

    if (!INTERCEPT_FUNCTION(__rust_realloc)) {
        intercept_successful = false;
        std::cout << "Failed to intercept __rust_realloc" << std::endl;
    }

    if (!INTERCEPT_FUNCTION(__rust_alloc_zeroed)) {
        intercept_successful = false;
        std::cout << "Failed to intercept __rust_alloc_zeroed" << std::endl;
    }

    return intercept_successful;
}

// TODO : Add method for getting calling function or location. Want to be able to patch allocation sites.
INTERCEPTOR(void*, __rust_alloc, size_t size, size_t align) {
    void* alloc_address = REAL(__rust_alloc)(size, align);
    GlobalHandler.track_alloc(alloc_address, size, align);
    return alloc_address;
}

INTERCEPTOR(void, __rust_dealloc, void* ptr, size_t size, size_t align) {
    GlobalHandler.untrack_alloc(ptr, size, align);
    return REAL(__rust_dealloc)(ptr, size, align);
}

INTERCEPTOR(void*, __rust_realloc, void* ptr, size_t old_size, size_t align, size_t new_size) {
    void* realloc_address = REAL(__rust_realloc)(ptr, old_size, align, new_size);
    GlobalHandler.track_realloc(ptr, old_size, realloc_address, new_size, align);
    return realloc_address;
}

INTERCEPTOR(void*, __rust_alloc_zeroed, size_t size, size_t align) {
    void* alloc_address = REAL(__rust_alloc_zeroed)(size, align);
    GlobalHandler.track_alloc(alloc_address, size, align);
    return alloc_address;
}