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
    __sanitizer::Report("INFO : No faulting instructions to export, returning.\n"); 
    return;
  }

  // TODO (mitch) : Not sure if this will lead to overlapping or 
  // overwritten files in between tests in a testing suite. If it 
  // does, we should switch to fstream and appending (or unique filenames).
  llvm::json::Value jFaultAllocs = llvm::json::Array(jAllocVec);
  std::error_code EC;
  llvm::StringRef Filename("FaultingAllocs.json");
  llvm::raw_fd_ostream OS(Filename, EC);

  OS << llvm::formatv("{0:2}", jFaultAllocs);
  OS.flush();
  OS.close();

  auto stats = StatsTracker::init();

  llvm::StringRef StatsName("RuntimeStats.txt");
  llvm::raw_fd_ostream SOS(StatsName, EC);
  SOS << "Number of Unique AllocSites Found: " << stats->AllocSitesFound.size() << "\n"
      << "Number of Unique ReallocSites Found: " << stats->ReallocSitesFound.size() << "\n"
      << "Number of Times allocHook Called: " << stats->allocHookCalls << "\n"
      << "Number of Times reallocHook Called: " << stats->reallocHookCalls << "\n"
      << "Number of Times deallocHook Called: " << stats->deallocHookCalls << "\n";
  
  for (auto &key_value : stats->AllocSiteFaultCount) {
    SOS << "AllocSite(" << key_value.first->id() << ") faults: " << key_value.second << "\n";
  }

  SOS.flush();
  SOS.close();
}

llvm::json::Value toJSON(AllocSite as) {
  return llvm::json::Object{
      {"id", as.id()},
      {"pkey", as.getPkey()},
  };
}

} // namespace __mpk_untrusted