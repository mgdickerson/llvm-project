// define a macro so that we can access register indexes from ucontext.h
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>

#define PAGE_SIZE 4096
#define TF 0x100
#define si_pkey_offset 0x20

void segv_handler(int signal, siginfo_t* si, void* vucontext)
{
    printf("Enter SEGV Handler\n");

    uint64_t mask = ~(PAGE_SIZE - 1);
    // Obtains pointer causing fault
    void* ptr = si->si_addr;
    uintptr_t ptr_val = (uintptr_t)ptr;

    printf("ptr = %p\n", ptr);
    void* aligned_ptr = (void*)(ptr_val & mask);
    printf("aligned_tpr = %p\n", aligned_ptr);
    mprotect(aligned_ptr, PAGE_SIZE, PROT_READ | PROT_WRITE);

    printf("mprotect() done\n");
    // set trap flag

    ucontext_t* uctxt = vucontext;
    // set trap flag on next instruction
    uctxt->uc_mcontext.gregs[REG_EFL] |= TF;
}

void trap_handler(int signal, siginfo_t* si, void* vucontext)
{
    printf("handling a trap!\n");
    ucontext_t* uctxt = vucontext;
    // clear trap flag so we can restore pkru regiser
    uctxt->uc_mcontext.gregs[REG_EFL] &= ~TF;
}

//TODO: refactor to use w/ GTEST
int main()
{
    struct sigaction sa_segv;

    sa_segv.sa_flags = SA_SIGINFO;
    sigemptyset(&sa_segv.sa_mask);
    sa_segv.sa_sigaction = segv_handler;
    if (sigaction(SIGSEGV, &sa_segv, NULL) == -1) {
        printf("Failed to register sigaction for SIGSEGV\n.");
        return -1;
    }

    struct sigaction sa_trap;

    sa_trap.sa_flags = SA_SIGINFO;
    sigemptyset(&sa_trap.sa_mask);
    sa_trap.sa_sigaction = trap_handler;
    if (sigaction(SIGTRAP, &sa_trap, NULL) == -1) {
        printf("Failed to register sigaction for SIGTRAP\n.");
        return -1;
    }

    char* ptr = mmap(NULL, PAGE_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (ptr == MAP_FAILED) {
        printf("mmap failed\n");
        return -1;
    }
    printf("ptr = %p\n", ptr);

    strncpy(ptr, "hello world!", 1024);

    printf("*ptr = '%s'\n", ptr);
    return 0;
}
