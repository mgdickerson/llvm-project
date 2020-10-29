#ifndef MPKSEGFAULTHANDLER_H
#define MPKSEGFAULTHANDLER_H

#include <csignal>

extern void segMPKHandle(int signal, siginfo_t *si, void *arg);

#endif
