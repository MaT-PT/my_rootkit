#include <asm-generic/errno-base.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>

#include "mem-protect.h"

void cr0_write(unsigned long val)
{
    asm volatile("mov %0,%%cr0"
            : "+r"(val)
            :
            : "memory");
}

inline unsigned long unprotect_memory(void)
{
    unsigned long orig_cr0;
    unsigned long new_cr0;

    orig_cr0 = native_read_cr0(); // in special_insns.h
    new_cr0 = orig_cr0 & ~(X86_CR0_WP); // in processor-flags.h
    cr0_write(new_cr0);
    return orig_cr0;
}

inline void protect_memory(unsigned long orig_cr0)
{
    cr0_write(orig_cr0);
}
