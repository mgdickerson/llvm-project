include(CheckCXXCompilerFlag)
include(CompilerRTCompile)
include(CompilerRTLink)

include_directories(..)
include_directories(../..)

add_custom_target(MPKUnitTests)
set_target_properties(MPKUnitTests PROPERTIES
	FOLDER "Compiler-rt Tests")

message(STATUS "COMPILER_RT_SOURCE_DIR : ${COMPILER_RT_SOURCE_DIR}")

set(MPK_UNITTEST_CFLAGS
	${MPK_UNTRUSTED_CFLAGS}
	${COMPILER_RT_UNITTEST_CFLAGS}
	${COMPILER_RT_GTEST_CFLAGS}
	-I${COMPILER_RT_SOURCE_DIR}/include
	-I${COMPILER_RT_SOURCE_DIR}/lib
	-I${COMPILER_RT_SOURCE_DIR}/lib/mpk_untrusted)

set(MPK_TEST_ARCH ${X86_64})
set(LINK_FLAGS
	-lstdc++
	-lm)

set(MPK_RTL_HEADERS)
foreach (header ${MPK_UNTRUSTED_HEADERS})
	list(APPEND MPK_RTL_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/../${header})
endforeach()
message(STATUS "MPK_RTL_HEADERS : ${MPK_RTL_HEADERS}")

macro(add_mpk_unittest testname)
	cmake_parse_arguments(TEST "" "" "SOURCES;HEADERS" ${ARGN})
	message(STATUS "Building Source : ${TEST_SOURCES}")
	set(MPKUnitTestObjects)
	generate_compiler_rt_tests(MPKUnitTestObjects MPKUnitTests
		"${testname}-${MPK_TEST_ARCH}-Test" ${MPK_TEST_ARCH}
		SOURCES ${TEST_SOURCES} ${COMPILER_RT_GTEST_SOURCE}
		RUNTIME ${MPK_TEST_RUNTIME}
		COMPILE_DEPS ${TEST_HEADERS} ${MPK_RTL_HEADERS}
		DEPS gtest mpk_untrusted
		CFLAGS ${MPK_UNITTEST_CFLAGS}
		LINK_FLAGS ${LINK_FLAGS})
	message(STATUS "Making test : ${testname} as ${testname}-${MPK_TEST_ARCH}-Test")
endmacro()

add_subdirectory(sig)

#set(PWD ${CMAKE_BINARY_DIR}/../compiler-rt/lib/mpk_untrusted/tests/)

#set(MPK_UNITTEST_SOURCES
#	${PWD}/sig/src/sig.c)
#set(MPK_UNITTEST_HEADERS
#	${PWD}/util/mpk_untrusted_test_config.h)

#find_library (MPK_LIB NAMES libclang_rt.mpk_untrusted-x86_64.a ${CMAKE_BINARY_DIR})
#message(STATUS "MPK_LIB PATH : ${MPK_LIB}")
#message(STATUS "PWD : ${PWD}")

#set(MPK_UNTRUSTED_SUPPORTED_ARCH ${X86_64})
#set(MPK_UNTRUSTED_CFLAGS ${SANITIZER_COMMON_CFLAGS} ${COMPILER_RT_UNITTEST_CFLAGS} ${COMPILER_RT_GTEST_CFLAGS})
#set(MPK_UNTRUSTED_LINK_FLAGS 
#    ${SANITIZER_COMMON_LINK_FLAGS}
#    -lstdc++
#    -lm
#    -lrt
#    -ldl
#    -lpthread
#    -whole-archive
#    -l${MPK_LIB}
#    -no-whole-archive
#    )

#set(MPK_GTESTS)

# Main MPK_Untrusted unit tests.
#add_custom_target(MPKUnitTests)
#set_target_properties(MPKUnitTests PROPERTIES FOLDER "MPK unit tests")

#foreach(arch ${MPK_UNTRUSTED_SUPPORTED_ARCH})
#    set(MPK_GTEST_OBJECTS)
#    sanitizer_test_compile(
#	MPK_GTEST_OBJECTS ${COMPILER_RT_GTEST_SOURCE} ${arch}
#	KIND ""
#	COMPILE_DEPS ${MPK_UNITTEST_HEADERS}
#	DEPS gtest gtest_main
#	CFLAGS ${MPK_UNTRUSTED_CFLAGS})
#
#    sanitizer_test_compile(
#	MPK_OBJECTS ${MPK_UNITTEST_SOURCES} ${arch}
#        KIND ""
#        COMPILE_DEPS ${MPK_UNITTEST_HEADERS}
#        DEPS gtest gtest_main
#        CFLAGS ${MPK_UNTRUSTED_CFLAGS}
#    )
#
#    set(MPK_BUILD_OBJECTS ${MPK_GTEST_OBJECTS} ${MPK_OBJECTS})
#
#    add_compiler_rt_test(MPKUnitTests "mpk-${arch}-tests" ${arch}
#    OBJECTS ${MPK_BUILD_OBJECTS}
#    DEPS ${MPK_GTEST_OBJECTS}
#    LINK_FLAGS ${MPK_UNTRUSTED_LINK_FLAGS})
#endforeach()
