#include "mpk_formatter.h"

namespace __mpk_untrusted {

bool writeUniqueFile(std::set<AllocSite>& faultSet) {
  // TODO : How to guarantee we dump everything in the same testing folder.
  std::string TestDirectory = "TestResults";
  if (!llvm::sys::fs::is_directory(TestDirectory))
    llvm::sys::fs::create_directory(TestDirectory);
  
  llvm::Expected<llvm::sys::fs::TempFile> TempFaults =
      llvm::sys::fs::TempFile::create(TestDirectory + "/faulting-allocs-%%%%%%%.json");
  if (!TempFaults) {
    __sanitizer::Report("Error making unique filename: %s\n", llvm::toString(TempFaults.takeError()).c_str());
    return false;
  }

  std::vector<AllocSite> allocVec(faultSet.begin(), faultSet.end());
  llvm::json::Value jFaultVec = llvm::json::Array(allocVec);
  llvm::raw_fd_ostream OS(TempFaults->FD, /* shouldClose */ false);
  OS << llvm::formatv("{0:2}", jFaultVec);
  OS.flush();
  
  llvm::Expected<llvm::sys::fs::TempFile> TempStats =
      llvm::sys::fs::TempFile::create(TestDirectory + "/runtime-stats-%%%%%%%.stat");
  if (!TempStats) {
    __sanitizer::Report("Error making unique filename: %s\n", llvm::toString(TempStats.takeError()).c_str());
    return false;
  }

  auto stats = StatsTracker::init();
  llvm::raw_fd_ostream SOS(TempStats->FD, /* shouldClose */ false);
  SOS << "Number of Unique AllocSites Found: " << stats->AllocSitesFound.size() << "\n"
      << "Number of Unique ReallocSites Found: " << stats->ReallocSitesFound.size() << "\n"
      << "Number of Times allocHook Called: " << stats->allocHookCalls << "\n"
      << "Number of Times reallocHook Called: " << stats->reallocHookCalls << "\n"
      << "Number of Times deallocHook Called: " << stats->deallocHookCalls << "\n";
  for (auto &key_value : stats->AllocSiteFaultCount) {
    SOS << "AllocSite(" << key_value.first->id() << ") faults: " << key_value.second << "\n";
  }
  SOS.flush();

  if (auto E = TempFaults->keep()) {
    __sanitizer::Report("Error keeping unique faults file: %s\n", llvm::toString(std::move(E)).c_str());
    return false;
  }
  if (auto E = TempStats->keep()) {
    __sanitizer::Report("Error keeping runtime stats file: %s\n", llvm::toString(std::move(E)).c_str());
    return false;
  }

  return true;
}

// Flush Allocs is to be called on program exit to flush all faulting
// allocations to disk/file.
void flushAllocs() {
  auto handler = AllocSiteHandler::init();
  if (handler->faultingAllocs().empty()) {
    __sanitizer::Report("INFO : No faulting instructions to export, returning.\n"); 
    return;
  }

  // Simple method that requires either handling multiple files or a script for combining them later.
  if (!writeUniqueFile(handler->faultingAllocs()))
    __sanitizer::Report("ERROR : Unable to successfully write unique files for given program run.\n");
}

llvm::json::Value toJSON(AllocSite as) {
  return llvm::json::Object{
      {"id", as.id()},
      {"pkey", as.getPkey()},
  };
}

} // namespace __mpk_untrusted