#ifndef MPK_FORMATTER_H
#define MPK_FORMATTER_H

#include "alloc_site_handler.h"

// TODO : See if this makes includes and builds easier.
#include "fstream"

#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"

namespace __mpk_untrusted {

void flushAllocs();

llvm::json::Value toJSON(AllocSite as);

} // namespace __mpk_untrusted

#endif