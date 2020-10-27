#ifndef MPKUNTRUSTED_H
#define MPKUNTRUSTED_H

#include "mpk_fault_handler.h"
#include "mpk_common.h"

extern "C" {
    __attribute__((visibility("default"))) static void mpk_untrusted_constructor();
    __attribute__((visibility("default"))) static void __attribute__((constructor)) mpk_untrusted();
}

#endif
