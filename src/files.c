#include "files.h"

#include "macro_utils.h"
#include <asm-generic/errno-base.h>
#include <asm/current.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kstrtox.h>
#include <linux/path.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

bool is_process_file(const file_t *const p_file, const char **const ps_name, pid_t *p_pid)
{
    int i_res                = 0;    // Result of `kstrtoint()` (0 on success)
    const dentry_t *p_parent = NULL; // Parent dentry structure
    pid_t i32_pid            = -1;   // PID of the process found in the path, if any

    IF_U (!is_proc_descendant(p_file)) {
        if (ps_name != NULL) {
            *ps_name = NULL;
        }
        if (p_pid != NULL) {
            *p_pid = -1;
        }
        return false;
    }

    p_parent = p_file->f_path.dentry;

    // Go up the directory tree until we reach a direct child of the root
    while (!IS_ROOT(p_parent->d_parent)) {
        p_parent = p_parent->d_parent;
    }

    // Check if the parent directory is /proc/<pid>, with <pid> being a number
    i_res = kstrtoint(p_parent->d_name.name, 10, &i32_pid);

    if (ps_name != NULL) {
        // Set ps_name to the name of the first directory in the path after its root
        *ps_name = p_parent->d_name.name;
    }

    if (p_pid != NULL) {
        // Set p_pid to the corresponding PID, if this is a process file
        *p_pid = i_res ? -1 : i32_pid;
    }

    return i_res == 0;
}

const file_t *fd_get_file(const int d_fd)
{
    const file_t *p_file = NULL;           // File structure
    files_t *p_files     = current->files; // Reference to the current task files

    IF_U (p_files == NULL) {
        // If the current task has no files, return an error (this should not happen)
        return ERR_PTR(-ENOENT);
    }

    IF_U (d_fd < 0) {
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

const char *file_get_pathname(const file_t *const p_file)
{
    const char *s_pathname     = NULL; // Pathname of the file
    const char *s_pathname_ret = NULL; // Pathname of the file (return value)
    char *p_tmp                = NULL; // Temporary buffer for `d_path()`
    const path_t *p_path       = NULL; // Path structure

    IF_U (p_file == NULL) {
        return ERR_PTR(-EINVAL);
    }

    p_path = &p_file->f_path;
    path_get(p_path); // Increment the path reference count while we use it

    p_tmp = (char *)__get_free_page(GFP_KERNEL);

    IF_U (p_tmp == NULL) {
        path_put(p_path); // Release the path structure
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

const char *fd_get_pathname(const int d_fd)
{
    const file_t *p_file = NULL; // File structure

    p_file = fd_get_file(d_fd);
    IF_U (IS_ERR(p_file)) {
        return (char *)p_file;
    }

    return file_get_pathname(p_file);
}
