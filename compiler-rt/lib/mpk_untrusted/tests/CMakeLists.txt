include(CheckCXXCompilerFlag)
include(CompilerRTCompile)
include(CompilerRTLink)

include_directories(..)
include_directories(../..)
include_directories(util)

add_custom_target(MPKUnitTests)
set_target_properties(MPKUnitTests PROPERTIES
	FOLDER "Compiler-rt Tests")

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
	-lpthread
	-lm)

set(MPK_RTL_HEADERS)

macro(add_mpk_unittest testname)
	cmake_parse_arguments(TEST "" "" "SOURCES;HEADERS" ${ARGN})
	message(STATUS "Building Source : ${TEST_SOURCES}")
	foreach(arch ${MPK_TEST_ARCH})
		set(MPKUnitTestObjects)
		generate_compiler_rt_tests(MPKUnitTestObjects MPKUnitTests
			"${testname}-${arch}-Test" ${arch}
			SOURCES ${TEST_SOURCES} ${COMPILER_RT_GTEST_SOURCE}
			RUNTIME ${MPK_TEST_RUNTIME}
			COMPILE_DEPS ${TEST_HEADERS} ${MPK_RTL_HEADERS}
			DEPS gtest mpk_untrusted
			CFLAGS ${MPK_UNITTEST_CFLAGS}
			LINK_FLAGS ${LINK_FLAGS})
		message(STATUS "Making test : ${testname} as ${testname}-${arch}-Test")
	endforeach()
endmacro()

add_subdirectory(sig)
