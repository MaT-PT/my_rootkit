#ifndef _ROOTKIT_ROOTKIT_MAIN_H_
#define _ROOTKIT_ROOTKIT_MAIN_H_

#include <asm/ptrace.h>

typedef void *(*kallsyms_t)(const char *s_name);
typedef long (*sysfun_t)(struct pt_regs *p_regs);

long new_read(struct pt_regs *p_regs);
long new_write(struct pt_regs *p_regs);
long new_open(struct pt_regs *p_regs);

#endif
