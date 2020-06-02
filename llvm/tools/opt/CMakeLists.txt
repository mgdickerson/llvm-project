set(LLVM_LINK_COMPONENTS
  ${LLVM_TARGETS_TO_BUILD}
  AggressiveInstCombine
  Analysis
  BitWriter
  CodeGen
  Core
  Coroutines
  IPO
  IRReader
  InstCombine
  Instrumentation
  MC
  ObjCARCOpts
  ScalarOpts
  Support
  Target
  TransformUtils
  Vectorize
  Passes
  )

# Support plugins.
set(LLVM_NO_DEAD_STRIP 1)

add_llvm_tool(opt
  AnalysisWrappers.cpp
  BreakpointPrinter.cpp
  Debugify.cpp
  GraphPrinters.cpp
  NewPMDriver.cpp
  PassPrinters.cpp
  PrintSCC.cpp
  opt.cpp

  DEPENDS
  intrinsics_gen
  )
export_executable_symbols(opt)

if(WITH_POLLY AND LINK_POLLY_INTO_TOOLS)
  target_link_libraries(opt PRIVATE Polly)
endif(WITH_POLLY AND LINK_POLLY_INTO_TOOLS)


if(WITH_SEA_DSA AND LINK_SEA_DSA_INTO_TOOLS)
  target_link_libraries(opt PRIVATE SeaDsaAnalysis)
endif(WITH_SEA_DSA AND LINK_SEA_DSA_INTO_TOOLS)


if(WITH_PHASAR AND LINK_PHASAR_INTO_TOOLS)
  target_link_libraries(opt PRIVATE untrusted_pass)
endif(WITH_PHASAR AND LINK_PHASAR_INTO_TOOLS)
