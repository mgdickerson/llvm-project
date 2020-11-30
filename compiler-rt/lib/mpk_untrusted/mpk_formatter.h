#ifndef MPK_FORMATTER_H
#define MPK_FORMATTER_H

#include "alloc_site_handler.h"

#include "fstream"
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

namespace __mpk_untrusted {

void flushAllocs();

} // namespace __mpk_untrusted

#endif