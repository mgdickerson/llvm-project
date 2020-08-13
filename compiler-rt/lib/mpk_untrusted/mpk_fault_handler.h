#include "alloc_site_handler.h"
#include <signal.h>
#include <cstdint>
#include <stdio.h>

static void segMPKHandle(int signal, siginfo_t *si, void *arg);