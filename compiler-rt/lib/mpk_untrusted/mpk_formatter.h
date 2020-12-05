#ifndef MPK_FORMATTER_H
#define MPK_FORMATTER_H

#include "alloc_site_handler.h"

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

void flushAllocs();

} // namespace __mpk_untrusted

#endif