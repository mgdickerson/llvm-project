#ifndef MPKUNTRUSTED_H
#define MPKUNTRUSTED_H

#include "mpk_fault_handler.h"
#include "mpk_formatter.h"
#include "mpk_common.h"
#include "sanitizer_common/sanitizer_common.h"

#include <cstring>

extern "C" {
extern uint64_t AllocSiteTotal;

__attribute__((visibility("default"))) void mpk_untrusted_constructor();
}

#endif
