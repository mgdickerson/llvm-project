#ifndef MPKSEGFAULTHANDLER_H
#define MPKSEGFAULTHANDLER_H

#include "mpk_common.h"

extern void segMPKHandle(int sig, siginfo_t *si, void *arg);
extern void stepMPKHandle(int sig, siginfo_t *si, void *arg);

#endif
