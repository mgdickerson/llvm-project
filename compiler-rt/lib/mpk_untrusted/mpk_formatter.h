#ifndef MPK_FORMATTER_H
#define MPK_FORMATTER_H

#include "alloc_site_handler.h"
#include "mpk_common.h"

#include "llvm/ADT/Optional.h"
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace __mpk_untrusted {

void flush_allocs();

} // namespace __mpk_untrusted

extern "C" {
__attribute__((visibility("default"))) static void __attribute__((constructor)) register_flush_allocs();
}

#endif