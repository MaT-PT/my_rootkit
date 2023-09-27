#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>

#define VERSION_MODIFIED _IO(0, 0)
#define VERSION_RESET _IO(0, 1)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Matthieu Hiver");
MODULE_DESCRIPTION("A module that creates a /dev/version device");
MODULE_VERSION("0.1");

char msg[256];
size_t msg_size;
bool modified;

void reset_version(void) {
    snprintf(msg, sizeof(msg), "%s\n", init_utsname()->release);
    msg_size = strlen(msg) * sizeof(char);
    modified = false;
}

ssize_t version_read(struct file *file, char __user *buf, size_t count, loff_t *off) {
    if (*off >= msg_size) {
        return 0;
    }
    if (*off + count > msg_size) {
        count = msg_size - *off;
    }
    if (copy_to_user(buf, msg + *off, count)) {
        return -EFAULT;
    }

    *off += count;
    return count;
}

ssize_t version_write(struct file *file, const char __user *buf, size_t count, loff_t *off) {
    if (count + *off > sizeof(msg)) {
        return -EINVAL;
    }
    if (copy_from_user(msg + *off, buf, count)) {
        return -EFAULT;
    }

    *off += count;
    msg[*off] = '\0';
    msg_size = strlen(msg) * sizeof(char);
    modified = true;
    return count;
}

static long version_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case VERSION_MODIFIED:
            return modified;

        case VERSION_RESET:
            reset_version();
            return 0;

        default:
            return -EINVAL;
    }
}

static struct file_operations version_fops = {
    .owner = THIS_MODULE,
    .read = version_read,
    .write = version_write,
    .unlocked_ioctl = version_ioctl,
};

static struct miscdevice version_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "version",
    .fops = &version_fops,
    .mode = 0644,  // rw-r--r--
};

static __init int version_init(void) {
    int reg_err;

    reg_err = misc_register(&version_dev);
    if (reg_err) {
        pr_err("Unable to register \"version\" misc device\n");
        return reg_err;
    }
    pr_info("\"version\" misc device registered\n");

    reset_version();

    return 0;
}

static __exit void version_exit(void) {
    misc_deregister(&version_dev);
    pr_info("\"version\" misc device unregistered\n");
    return;
}

module_init(version_init);
module_exit(version_exit);
