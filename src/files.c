#include "inc/files.h"

#include "inc/macro_utils.h"
#include <asm/current.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

// TODO: Function to check if two files are the same (same inode/device/etc.)

const file_t *fd_get_file(int d_fd)
{
    const file_t *p_file = NULL;           // File structure
    files_t *p_files     = current->files; // Reference to the current task files

    IF_U (p_files == NULL) {
        // If the current task has no files, return an error (this should not happen)
        return ERR_PTR(-ENOENT);
    }

    IF_U (d_fd < 0 || d_fd >= p_files->fdt->max_fds) {
        // If the file descriptor is invalid, return an error
        return ERR_PTR(-EBADF);
    }

    spin_lock(&p_files->file_lock); // Lock the files structure while we use it
    p_file = lookup_fd_rcu(d_fd);
    spin_unlock(&p_files->file_lock);

    IF_U (p_file == NULL) {
        return ERR_PTR(-ENOENT);
    }

    return p_file;
}

const char *fd_get_pathname(int d_fd)
{
    const char *s_pathname     = NULL; // Pathname of the file
    const char *s_pathname_ret = NULL; // Pathname of the file (return value)
    char *p_tmp                = NULL; // Temporary buffer
    const file_t *p_file       = NULL; // File structure
    const path_t *p_path       = NULL; // Path structure

    p_file = fd_get_file(d_fd);
    IF_U (IS_ERR(p_file)) {
        return (char *)p_file;
    }

    p_path = &p_file->f_path;
    path_get(p_path); // Increment the path reference count while we use it

    p_tmp = (char *)__get_free_page(GFP_KERNEL);

    IF_U (p_tmp == NULL) {
        path_put(p_path);
        return ERR_PTR(-ENOMEM);
    }

    s_pathname = d_path(p_path, p_tmp, PAGE_SIZE);
    path_put(p_path);

    IF_U (IS_ERR(s_pathname)) {
        free_page((unsigned long)p_tmp);
        return s_pathname;
    }

    s_pathname_ret = kstrdup_const(s_pathname, GFP_KERNEL);

    free_page((unsigned long)p_tmp);
    return s_pathname_ret;
}
