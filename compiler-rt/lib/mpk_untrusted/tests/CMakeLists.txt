include(CheckCXXCompilerFlag)
include(CompilerRTCompile)
include(CompilerRTLink)

include_directories(..)
include_directories(../..)

set(MPK_UNITTEST_SOURCES
    /sig/src/sig.c)
set(MPK_UNITTEST_HEADERS
    /util/mpk_untrusted_test_config.h)

find_library (MPK_LIB NAMES libclang_rt.mpk_untrusted-x86_64.a PATHS CMAKE_BINARY_DIR/lib/clang)
message(STATUS "MPK_LIB PATH : ${MPK_LIB}")

set(MPK_UNTRUSTED_SUPPORTED_ARCH ${X86} ${X86_64})
set(MPK_UNTRUSTED_CFLAGS ${SANITIZER_COMMON_CFLAGS} ${COMPILER_RT_UNITTEST_CFLAGS} ${COMPILER_RT_GTEST_CFLAGS})
set(MPK_UNTRUSTED_LINK_FLAGS 
    ${SANITIZER_COMMON_LINK_FLAGS}
    -lstdc++
    -lm
    -lrt
    -ldl
    -lpthread
    -whole-archive
    -l${MPK_LIB}
    -no-whole-archive
    )

set(MPK_GTESTS)
foreach(arch ${MPK_UNTRUSTED_SUPPORTED_ARCH})
    sanitizer_test_compile(
        MPK_GTEST_OBJECTS ${MPK_UNITTEST_SOURCES} ${arch}
        KIND ""
        COMPILE_DEPS ${MPK_UNITTEST_HEADERS}
        DEPS gtest gtest_main
        CFLAGS ${MPK_UNTRUSTED_CFLAGS}
    )

    add_compiler_rt_test(MPKUnitTests "mpk-${arch}-tests" ${arch}
    OBJECTS ${MPK_GTEST_OBJECTS}
    DEPS ${MPK_GTEST_OBJECTS}
    LINK_FLAGS ${MPK_UNTRUSTED_LINK_FLAGS})
endforeach()