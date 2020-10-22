// mpk.cpp
//
// Copyright 2018 Paul Kirth
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// This file supplies a set of APIs similar or identical to those found in glibc-2.27
// We mimic these for future compatibility with standard libraries.

// set to 1 if we can use the same implementation for pkey_mprotect as glibc-2.27

#include "mpk.h"

#include <cerrno>
#include <cstdio>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace __mpk_untrusted {
    /* Return the value of the PKRU register.  */
    inline unsigned int pkey_read()
    {
#if HAS_MPK
        unsigned int result;
        __asm__ volatile(".byte 0x0f, 0x01, 0xee" : "=a"(result) : "c"(0) : "rdx");
        return result;
#else
        return 0;
#endif
    }

    /* Overwrite the PKRU register with VALUE.  */
    inline void pkey_write(unsigned int pkru)
    {
#if HAS_MPK
        unsigned int eax = pkru;
        unsigned int ecx = 0;
        unsigned int edx = 0;

        asm volatile(".byte 0x0f,0x01,0xef\n\t" : : "a"(eax), "c"(ecx), "d"(edx));
#endif
    }

    /*return the set bits of pkru for the input key */
    int pkey_get(int key)
    {
#if HAS_MPK
        if(key < 0 || key > 15)
        {
            errno = EINVAL;
            return -1;
        }
        unsigned int pkru = pkey_read();
        return (pkru >> (2 * key)) & 3;
#else
        return 0;
#endif
    }

    /* set the bits in pkru for key using rights */
    int pkey_set(int key, unsigned int rights)
    {
#if HAS_MPK
        if(key < 0 || key > 15 || rights > 3)
        {
            errno = EINVAL;
            return -1;
        }
        unsigned int mask = 3 << (2 * key);
        unsigned int pkru = pkey_read();
        pkru              = (pkru & ~mask) | (rights << (2 * key));
        pkey_write(pkru);
#endif
        return 0;
    }

    int pkey_mprotect(void* addr, size_t len, int prot, int pkey)
    {
#if HAS_MPK
        return syscall(SYS_pkey_mprotect, addr, len, prot, pkey);
#else
        return syscall(SYS_mprotect, addr, len, prot);
#endif
    }

    int pkey_alloc()
    {
#if HAS_MPK
        return syscall(SYS_pkey_alloc, 0, 0);
#else
        return 0;
#endif
    }

    int pkey_free(unsigned long pkey)
    {
#if HAS_MPK
        return syscall(SYS_pkey_free, pkey);
#else
        return 0;
#endif
    }
}