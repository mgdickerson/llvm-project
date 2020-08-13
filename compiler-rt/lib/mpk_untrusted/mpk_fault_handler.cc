#include "mpk_fault_handler.h"

#define XSTATE_PKRU_BIT (9)

static void segMPKHandle(int signal, siginfo_t *si, void *arg) {
    ucontext_t *uctxt = (ucontext_t *)arg;
    fpregset_t fpregset = uctxt->uc_mcontext.fpregs;
    char *fpregs = (char *)fpregset;
    int pkru_offset = pkru_xstate_offset();

    // Obtains the pkru pointer for current segfault handle
    uint32_t *pkru_ptr = (uint32_t *)(&fpregs[pkru_offset]);

	// Obtains pointer causing fault
	void *ptr = si->si_addr;

    // Deactivate pkru key for current page
    printf("Reached MPK SegFault for address: %p.\n", ptr);
}

static inline void __cpuid(unsigned int *eax, unsigned int *ebx,
                            		unsigned int *ecx, unsigned int *edx)
{
  	/* ecx is often an input as well as an output. */
    	asm volatile(
                     		"cpuid;"
                     		: "=a" (*eax),
                     		  "=b" (*ebx),
                     		  "=c" (*ecx),
                     		  "=d" (*edx)
                     		: "0" (*eax), "2" (*ecx));
}

static inline int pkru_xstate_offset(void)
{
  	unsigned int eax;
  	unsigned int ebx;
  	unsigned int ecx;
  	unsigned int edx;
  	int xstate_offset;
  	int xstate_size;
  	unsigned long XSTATE_CPUID = 0xd;
  	int leaf;
    /* assume that XSTATE_PKRU is set in XCR0 */
    leaf = XSTATE_PKRU_BIT;
  	{
    		eax = XSTATE_CPUID;
    		ecx = leaf;
    		__cpuid(&eax, &ebx, &ecx, &edx);
      		xstate_offset = ebx;
      		xstate_size = eax;
    }
    if (xstate_size == 0) {
    	printf("could not find size/offset of PKRU in xsave state\n");
    	return 0;
    }
    return xstate_offset;
}

// inline static void pkey_init()
// {
//   for(int i = 0 ; i < PKEY_MAX - 1 ; i++)
//   {
//       if(pkey_alloc(0,PKEY_DISABLE_WRITE) == -1)
//         errExit("pkey_alloc");
//   }
// }
