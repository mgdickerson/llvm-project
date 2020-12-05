#ifndef MPK_FORMATTER_H
#define MPK_FORMATTER_H

#include "alloc_site_handler.h"

// TODO : See if this makes includes and builds easier.
#include "fstream"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <time.h>
#include <string>

namespace __mpk_untrusted {

void flushAllocs();

} // namespace __mpk_untrusted

#endif