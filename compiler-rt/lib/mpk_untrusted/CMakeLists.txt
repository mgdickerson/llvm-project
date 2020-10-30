# Build for MPK Untrusted Dynamic Analysis

include_directories(..)

set(MPK_UNTRUSTED_SOURCES
    alloc_site_handler.cpp
    mpk.cpp
    mpk_fault_handler.cpp
    mpk_formatter.cpp
    mpk_untrusted.cpp
    )

set(MPK_UNTRUSTED_HEADERS
    alloc_site_handler.h
    mpk.h
    mpk_common.h
    mpk_fault_handler.h
    mpk_formatter.h
    mpk_untrusted.h
    )

set(MPK_UNTRUSTED_CFLAGS ${SANITIZER_COMMON_CFLAGS})
set(MPK_UNTRUSTED_LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS})
set(SUPPORT_LIB ${CMAKE_BINARY_DIR}/lib/libLLVMCore.a ${CMAKE_BINARY_DIR}/lib/libLLVMSupport.a ${CMAKE_BINARY_DIR}/lib/libLLVMDemangle.a)
set(MPK_UNTRUSTED_DYNAMIC_LIBS ${SANITIZER_CXX_ABI_LIBRARY} ${SANITIZER_COMMON_LINK_LIBS} ${SUPPORT_LIB} dl pthread rt m tinfo)

#add_compiler_rt_object_libraries(RTMPKUntrustedCommon
#    OS ${SANITIZER_COMMON_SUPPORTED_OS}
#    ARCHS ${SANITIZER_COMMON_SUPPORTED_ARCH}
#    SOURCES ${MPK_UNTRUSTED_SOURCES}
#    ADDITIONAL_HEADERS ${MPK_UNTRUSTED_HEADERS}
#    CFLAGS ${MPK_UNTRUSTED_CFLAGS}
#    )

#message(STATUS "MPK_UNTRUSTED_CFLAGS ${MPK_UNTRUSTED_CFLAGS}")
#message(STATUS "MPK_UNTRUSTED_LINK_FLAGS ${MPK_UNTRUSTED_LINK_FLAGS}")
#message(STATUS "MPK_UNTRUSTED_DYNAMIC_LIBS ${MPK_UNTRUSTED_DYNAMIC_LIBS}")
#message(STATUS "MPK_SUPPORTED_ARCHES ${MPK_UNTRUSTED_SUPPORTED_ARCH}")

add_compiler_rt_component(mpk_untrusted)
foreach(arch ${MPK_UNTRUSTED_SUPPORTED_ARCH})
    add_compiler_rt_runtime(clang_rt.mpk_untrusted
        STATIC
        ARCHS ${arch}
        SOURCES ${MPK_UNTRUSTED_SOURCES}
                $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
        ADDITIONAL_HEADERS ${MPK_UNTRUSTED_HEADERS}
        CFLAGS ${MPK_UNTRUSTED_CFLAGS}
        LINK_LIBS ${SUPPORT_LIB}
        PARENT_TARGET mpk_untrusted)

# TODO : Missing some files I need to include in order for shared library to build correctly.
    add_compiler_rt_runtime(clang_rt.mpk_untrusted
        SHARED
        ARCHS ${arch}
        SOURCES ${MPK_UNTRUSTED_SOURCES}
        ADDITIONAL_HEADERS ${MPK_UNTRUSTED_HEADERS}
        OBJECT_LIBS RTSanitizerCommon
                    RTSanitizerCommonLibc
        CFLAGS ${MPK_UNTRUSTED_CFLAGS}
        LINK_FLAGS ${MPK_UNTRUSTED_LINK_FLAGS}
        LINK_LIBS ${MPK_UNTRUSTED_DYNAMIC_LIBS}
        PARENT_TARGET mpk_untrusted)
endforeach()

add_subdirectory(tests)
