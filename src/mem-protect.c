#include <asm-generic/errno-base.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>

#include "mem-protect.h"

void cr0_write(unsigned long val)
{
	asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

inline unsigned long unprotect_memory(void)
{
	unsigned long ul_orig_cr0;
	unsigned long ul_new_cr0;

	ul_orig_cr0 = native_read_cr0(); // in special_insns.h
	ul_new_cr0 = ul_orig_cr0 & ~(X86_CR0_WP); // in processor-flags.h
	cr0_write(ul_new_cr0);
	return ul_orig_cr0;
}

inline void protect_memory(unsigned long ul_orig_cr0)
{
	cr0_write(ul_orig_cr0);
}
