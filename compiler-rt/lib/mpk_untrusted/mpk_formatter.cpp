#include "mpk_formatter.h"
#include "alloc_site_handler.h"
#include <bits/stdint-intn.h>
#include <bits/stdint-uintn.h>
#include <fstream>

namespace __mpk_untrusted {

#define ATTEMPTS 128

bool makeUniqueFile(std::string Model, std::ofstream &OS) {
  srand(time(NULL));
  // Loop for number of attempts just in case level of entropy is to low
  for (uint8_t attempt = 0; attempt != ATTEMPTS; ++attempt) {
    std::string unique = Model;
    for (uint32_t i=0, e = unique.length(); i!=e; ++i) {
      if (unique[i] == '%')
        unique[i] = "0123456789abcdef"[rand() & 15];
    }
    struct stat info;
    // If file does not already exist, create and return ofstream
    if (stat(unique.c_str(), &info) == -1) {
      OS.open(unique, std::ios_base::trunc);
      // Ensure we correctly opened OS ofstream
      if (OS)
        return true;
    }
  }

  // Failed to make unique name
  return false;
}

bool is_directory(std::string directory) {
  struct stat info;
  if (stat(directory.c_str(), &info) != 0) 
    return false;
  else if (info.st_mode & S_IFDIR)
    return true;
  else
    return false;
}

// Function for handwriting the JSON output we want (to remove dependency on llvm/Support).
void writeJSON(std::ofstream &OS, std::set<AllocSite>& faultSet) {
  OS << "[\n";
  int64_t items_remaining = faultSet.size();
  for (auto fault : faultSet) {
    --items_remaining;
    if (items_remaining <= 0) {
      // This is the last (or only) item, do not add comma
      OS << "{ \"id\": " << fault.id() << ", \"pkey\": " << fault.getPkey() << " }\n";
    } else {
      OS << "{ \"id\": " << fault.id() << ", \"pkey\": " << fault.getPkey() << " },\n";
    }
  }
  OS << "]\n";
}

bool writeUniqueFile(std::set<AllocSite>& faultSet) {
  std::string TestDirectory = "TestResults";
  if (!is_directory(TestDirectory)) {
    if (mkdir(TestDirectory.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
      __sanitizer::Report("Failed to create TestResults directory.\n");
      return false;
    }
  }

  std::ofstream OS;
  if (!makeUniqueFile(TestDirectory + "/faulting-allocs-%%%%%%%.json", OS))
    return false;
  writeJSON(OS, faultSet);
  OS.flush();

  auto stats = StatsTracker::init();
  std::ofstream SOS;
  if (!makeUniqueFile(TestDirectory + "/runtime-stats-%%%%%%%.stat", SOS))
    return false;
  SOS << "Number of Unique AllocSites Found: " << stats->AllocSitesFound.size() << "\n"
      << "Number of Unique ReallocSites Found: " << stats->ReallocSitesFound.size() << "\n"
      << "Number of Times allocHook Called: " << stats->allocHookCalls << "\n"
      << "Number of Times reallocHook Called: " << stats->reallocHookCalls << "\n"
      << "Number of Times deallocHook Called: " << stats->deallocHookCalls << "\n";
  for (auto &key_value : stats->AllocSiteFaultCount) {
    SOS << "AllocSite(" << key_value.first->id() << ") faults: " << key_value.second << "\n";
  }
  SOS.flush();
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

} // namespace __mpk_untrusted
