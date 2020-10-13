#include "alloc_site_handler.h"
#include <signal.h>
#include <cstdint>
#include <stdio.h>
#include "sanitizer_common.h"

static void segMPKHandle(int signal, siginfo_t *si, void *arg);