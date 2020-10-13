# Build for MPK Untrusted Dynamic Analysis

include_directories(..)

set(MPK_UNTRUSTED_SOURCES
    alloc_site_handler.cc
    mpk_fault_handler.cc
    )

set(MPK_UNTRUSTED_HEADERS
    alloc_site_handler.h
    mpk_fault_handler.h
    mpk_untrusted.h
    )

set(MPK_UNTRUSTED_CFLAGS ${SANITIZER_COMMON_CFLAGS})
set(MPK_UNTRUSTED_LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS})

add_compiler_rt_object_libraries(RTMPKUntrustedCommon
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${SANITIZER_COMMON_SUPPORTED_ARCH}
    SOURCES ${MPK_UNTRUSTED_SOURCES}
    ADDITIONAL_HEADERS ${MPK_UNTRUSTED_HEADERS}
    CFLAGS ${MPK_UNTRUSTED_CFLAGS}
    )

add_compiler_rt_component(mpk_untrusted)
foreach(arch ${SANITIZER_COMMON_SUPPORTED_ARCH})
    add_compiler_rt_runtime(clang_rt.mpk_untrusted
        STATIC
        ARCHS ${arch}
        SOURCES ${MPK_UNTRUSTED_SOURCES}
                $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
        ADDITIONAL_HEADERS ${MPK_UNTRUSTED_HEADERS}
        CFLAGS ${MPK_UNTRUSTED_CFLAGS}
        PARENT_TARGET mpk_untrusted)
endforeach()