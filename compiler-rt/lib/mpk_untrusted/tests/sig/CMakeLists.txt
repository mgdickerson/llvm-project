#project (sig)
#add_executable(sig src/sig.c)

set(SIG_SOURCES
	src/sig.c)
set(SIG_HEADERS
	../util/mpk_untrusted_test_config.h)

add_mpk_unittest(SigUnitTest
	SOURCES ${SIG_SOURCES}
	HEADERS ${SIG_HEADERS})