#include "mpk_formatter.h"

namespace __mpk_untrusted {

// Flush Allocs is to be called on program exit to flush all faulting
// allocations to disk/file.
void flushAllocs() {
  auto handler = AllocSiteHandler::init();

  std::vector<llvm::json::Value> jAllocVec;
  for (auto alloc : handler->faultingAllocs()) {
    jAllocVec.push_back(toJSON(alloc));
  }

  if (jAllocVec.empty()) {
    // TODO : This is for testing only to make sure JSON output works.
    __sanitizer::Report("INFO : Faulting alloc vector is empty, so we are "
                        "making a fault entry for testing.\n");
    jAllocVec.push_back(toJSON(*AllocSite::error()));

    // __sanitizer::Report("INFO : No faulting instructions to export,
    // returning.\n"); return;
  }

  llvm::json::Value jFaultAllocs = llvm::json::Array(jAllocVec);
  std::error_code EC;
  llvm::StringRef Filename("FaultingAllocs.json");
  llvm::raw_fd_ostream OS(Filename, EC);

  OS << llvm::formatv("{0:2}", jFaultAllocs);
  OS.flush();
  OS.close();
}

llvm::json::Value toJSON(AllocSite as) {
  return llvm::json::Object{
      {"id", as.id()},
      {"pkey", as.getPkey()},
  };
}

} // namespace __mpk_untrusted