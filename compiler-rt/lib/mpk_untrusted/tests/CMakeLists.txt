include(CompilerRTCompile)
include(CompilerRTLink)

include_directories(..)

set(MPK_UNITTEST_SOURCES
    /sig/src/sig.c
    ${COMPILER_RT_GTEST_SOURCE})
set(MPK_UNITTEST_HEADERS
    /util/mpk_untrusted_test_config.h)

find_library (MPK_LIB NAMES libclang_rt.mpk_untrusted-x86_64.a PATHS CMAKE_BINARY_DIR/lib/clang)

set(MPK_UNTRUSTED_SUPPORTED_ARCH ${X86} ${X86_64})
set(MPK_UNTRUSTED_CFLAGS ${SANITIZER_COMMON_CFLAGS})

set(MPK_GTESTS)
foreach(arch ${MPK_UNTRUSTED_SUPPORTED_ARCH})
    sanitizer_test_compile(
        MPK_GTESTS ${MPK_UNITTEST_SOURCES} ${arch}
        KIND ""
        COMPILE_DEPS ${MPK_UNITTEST_HEADERS}
        DEPS gtest gtest_main mpk_untrusted
        CFLAGS ${MPK_UNTRUSTED_CFLAGS}
    )
endforeach()