#ifndef MPK_FORMATTER_H
#define MPK_FORMATTER_H

#include "alloc_site_handler.h"

#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

namespace __mpk_untrusted {

void flushAllocs();

llvm::json::Value toJSON(AllocSite as);
bool fromJSON(const llvm::json::Value ASite, FaultingSite &F);

} //__mpk_untrusted

#endif