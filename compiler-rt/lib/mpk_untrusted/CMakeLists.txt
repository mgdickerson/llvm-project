# Build for MPK Untrusted Dynamic Analysis

include_directories(..)

set(MPK_UNTRUSTED_SOURCES
    dyn_interrupt.cc
    mpk_fault_handler.cc
    )

set(MPK_UNTRUSTED_HEADERS
    alloc_site_handler.h
    dyn_interrupt.h
    mpk_fault_handler.h
    mpk_untrusted.h
    )

set(MPK_UNTRUSTED_CFLAGS ${SANITIZER_COMMON_CFLAGS})

add_compiler_rt_object_libraries(RTMPKUntrusted
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${SANITIZER_COMMON_SUPPORTED_ARCH}
    SOURCES ${MPK_UNTRUSTED_SOURCES}
    ADDITIONAL_HEADERS ${MPK_UNTRUSTED_HEADERS}
    CFLAGS ${MPK_UNTRUSTED_CFLAGS}
    )