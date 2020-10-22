#ifndef MPKSEGFAULTHANDLER_H
#define MPKSEGFAULTHANDLER_H

#include "alloc_site_handler.h"
#include "sanitizer_common/sanitizer_common.h"
#include <cstdint>
#include <signal.h>
#include <stdio.h>

extern void segMPKHandle(int signal, siginfo_t *si, void *arg);

#endif
