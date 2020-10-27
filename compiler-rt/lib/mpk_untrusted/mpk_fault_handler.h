#ifndef MPKSEGFAULTHANDLER_H
#define MPKSEGFAULTHANDLER_H

#include "alloc_site_handler.h"
#include "mpk.h"
#include "mpk_common.h"

extern void segMPKHandle(int signal, siginfo_t *si, void *arg);

#endif
