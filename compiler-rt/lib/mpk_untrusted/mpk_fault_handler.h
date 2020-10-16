#ifndef MPKSEGFAULTHANDLER_H
#define MPKSEGFAULTHANDLER_H

#include "alloc_site_handler.h"
#include <signal.h>
#include <cstdint>
#include <stdio.h>
#include "sanitizer_common/sanitizer_common.h"

static void segMPKHandle(int signal, siginfo_t *si, void *arg);

#endif
