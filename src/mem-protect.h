#ifndef _ROOTKIT_MEM_PROTECT_H_
#define _ROOTKIT_MEM_PROTECT_H_

inline unsigned long unprotect_memory(void);
inline void protect_memory(unsigned long orig_cr0);

#endif
