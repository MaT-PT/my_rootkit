#include "files.h"

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

char *fd_get_pathname(int d_fd)
{
    char *s_pathname     = NULL;           // Pathname of the file
    char *s_pathname_ret = NULL;           // Pathname of the file (return value)
    char *p_tmp          = NULL;           // Temporary buffer
    file_t *p_file       = NULL;           // File structure
    path_t *p_path       = NULL;           // Path structure
    files_t *p_files     = current->files; // Pointer to the current task files

    if (unlikely(p_files == NULL)) {
        // If the current task has no files, return an error (this should not happen)
        return ERR_PTR(-ENOENT);
    }

    if (unlikely(d_fd < 0 || d_fd >= current->files->fdt->max_fds)) {
        // If the file descriptor is invalid, return an error
        return ERR_PTR(-EBADF);
    }

    // Special case for STDIN/STDOUT/STDERR
    switch (d_fd) {
    case 0:
        return kstrdup("STDIN", GFP_KERNEL);
        break;

    case 1:
        return kstrdup("STDOUT", GFP_KERNEL);
        break;

    case 2:
        return kstrdup("STDERR", GFP_KERNEL);
        break;
    }

    spin_lock(&p_files->file_lock); // Lock the files structure while we use it
    p_file = lookup_fd_rcu(d_fd);
    if (unlikely(p_file == NULL)) {
        spin_unlock(&p_files->file_lock);
        return ERR_PTR(-ENOENT);
    }

    p_path = &p_file->f_path;
    path_get(p_path); // Increment the path reference count while we use it
    spin_unlock(&p_files->file_lock);

    p_tmp = (char *)__get_free_page(GFP_KERNEL);

    if (unlikely(p_tmp == NULL)) {
        path_put(p_path);
        return ERR_PTR(-ENOMEM);
    }

    s_pathname = d_path(p_path, p_tmp, PAGE_SIZE);
    path_put(p_path);

    if (unlikely(IS_ERR(s_pathname))) {
        free_page((unsigned long)p_tmp);
        return s_pathname;
    }

    s_pathname_ret = kstrdup(s_pathname, GFP_KERNEL);

    free_page((unsigned long)p_tmp);
    return s_pathname_ret;
}
