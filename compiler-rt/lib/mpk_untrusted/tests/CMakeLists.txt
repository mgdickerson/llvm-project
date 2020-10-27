include(CompilerRTCompile)
include(CompilerRTLink)

include_directories(..)

set(MPK_UNITTEST_SOURCES
    /sig/src/sig.c
    ${COMPILER_RT_GTEST_SOURCE})
set(MPK_UNITTEST_HEADERS
    /util/mpk_untrusted_test_config.h)

