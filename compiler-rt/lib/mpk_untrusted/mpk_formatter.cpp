#include "mpk_formatter.h"
#include "alloc_site_handler.h"

namespace __mpk_untrusted {

#define ATTEMPTS 128
#define ENTROPY 16

llvm::Optional<std::string> makeUniqueFilename(std::string path,
                                               std::string base_name,
                                               std::string extension) {
  std::mt19937_64 mt_rand(time(NULL));

  // Loop for number of attempts just in case level of entropy is to low
  for (uint8_t attempt = 0; attempt != ATTEMPTS; ++attempt) {
    std::stringstream unique;
    unique << path << "/" << base_name << "-" << getpid() << "-"
           << std::setfill('0') << std::setw(ENTROPY) << std::hex << mt_rand()
           << "." << extension;
    struct stat info;
    // If file does not already exist, create and return ofstream
    if (stat(unique.str().c_str(), &info) == -1) {
      return unique.str();
    }
  }

  // Failed to make unique name
  __sanitizer::Report("Failed to make uniqueFileID.\n");
  return llvm::None;
}

llvm::Optional<std::ofstream> makeUniqueStream(std::string path,
                                               std::string base_name,
                                               std::string extension) {
  auto Filename = makeUniqueFilename(path, base_name, extension);
  if (!Filename)
    return llvm::None;

  std::ofstream OS;
  OS.open(Filename.getValue());
  if (OS)
    return OS;

  __sanitizer::Report("Failed to create uniqueOStream.\n");
  return llvm::None;
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

// Function for handwriting the JSON output we want (to remove dependency on
// llvm/Support).
void writeJSON(std::ofstream &OS, std::set<AllocSite> &faultSet) {
  if (faultSet.size() <= 0)
    return;

  OS << "[\n";
  int64_t items_remaining = faultSet.size();
  for (auto fault : faultSet) {
    --items_remaining;
    OS << "{ \"id\": " << fault.id() << ", \"pkey\": " << fault.getPkey()
       << " }" << (items_remaining ? "," : "") << "\n";
  }
  OS << "]\n";
}

bool writeUniqueFile(std::set<AllocSite> &faultSet) {
  std::string TestDirectory = "TestResults";
  if (!is_directory(TestDirectory)) {
    if (mkdir(TestDirectory.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
      __sanitizer::Report("Failed to create TestResults directory.\n");
      return false;
    }
  }

  auto OS = makeUniqueStream(TestDirectory, "faulting-allocs", "json");
  if (!OS)
    return false;
  writeJSON(OS.getValue(), faultSet);
  OS.getValue().flush();

  auto stats = StatsTracker::init();
  auto SOS = makeUniqueStream(TestDirectory, "runtime-stats", "stat");
  if (!SOS)
    return false;
  SOS.getValue() << "Number of Unique AllocSites Found: "
                 << stats->AllocSitesFound.size() << "\n"
                 << "Number of Unique ReallocSites Found: "
                 << stats->ReallocSitesFound.size() << "\n"
                 << "Number of Times allocHook Called: "
                 << stats->allocHookCalls << "\n"
                 << "Number of Times reallocHook Called: "
                 << stats->reallocHookCalls << "\n"
                 << "Number of Times deallocHook Called: "
                 << stats->deallocHookCalls << "\n";
  for (auto &key_value : stats->AllocSiteFaultCount) {
    SOS.getValue() << "AllocSite(" << key_value.first->id()
                   << ") faults: " << key_value.second << "\n";
  }
  SOS.getValue().flush();
  return true;
}

// Flush Allocs is to be called on program exit to flush all faulting
// allocations to disk/file.
void flushAllocs() {
  auto handler = AllocSiteHandler::init();
  if (handler->faultingAllocs().empty()) {
    __sanitizer::Report(
        "INFO : No faulting instructions to export, returning.\n");
    return;
  }

  // Simple method that requires either handling multiple files or a script for
  // combining them later.
  if (!writeUniqueFile(handler->faultingAllocs()))
    __sanitizer::Report("ERROR : Unable to successfully write unique files for "
                        "given program run.\n");
}

} // namespace __mpk_untrusted
