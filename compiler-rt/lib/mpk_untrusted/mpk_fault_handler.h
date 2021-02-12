#ifndef MPKSEGFAULTHANDLER_H
#define MPKSEGFAULTHANDLER_H

#include "mpk_common.h"
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif

#define gettid() ((pid_t)syscall(SYS_gettid))

namespace __mpk_untrusted {

extern void segMPKHandle(int sig, siginfo_t *si, void *arg);
extern void stepMPKHandle(int sig, siginfo_t *si, void *arg);

} // namespace __mpk_untrusted
#endif
