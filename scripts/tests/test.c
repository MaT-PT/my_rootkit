#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/mount.h>
#include <linux/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_FILE   "test.txt"
#define HIDDEN_FILE ".rootkit_test"

void test_open(void)
{
    int fd;
    int fd_cwd;

    fd_cwd = open(".", O_RDONLY | O_DIRECTORY | O_PATH);

    fd = syscall(SYS_open, TEST_FILE, O_RDONLY);
    printf("open   '" TEST_FILE "': %d\n", fd);
    close(fd);

    fd = syscall(SYS_openat, fd_cwd, TEST_FILE, O_RDONLY);
    printf("openat '" TEST_FILE "': %d\n", fd);
    close(fd);

    fd = syscall(SYS_creat, TEST_FILE, 0644);
    printf("creat  '" TEST_FILE "': %d\n", fd);
    close(fd);

    fd = syscall(SYS_open, HIDDEN_FILE, O_RDONLY);
    printf("open   '" HIDDEN_FILE "': %d\n", fd);
    close(fd);

    fd = syscall(SYS_openat, fd_cwd, HIDDEN_FILE, O_RDONLY);
    printf("openat '" HIDDEN_FILE "': %d\n", fd);
    close(fd);

    fd = syscall(SYS_creat, HIDDEN_FILE, 0644);
    printf("creat  '" HIDDEN_FILE "': %d\n", fd);
    close(fd);

    fd = syscall(SYS_open_tree, fd_cwd, TEST_FILE, OPEN_TREE_CLONE);
    printf("open_tree '" TEST_FILE "': %d\n", fd);
    close(fd);

    fd = syscall(SYS_open_tree, fd_cwd, HIDDEN_FILE, OPEN_TREE_CLONE);
    printf("open_tree '" HIDDEN_FILE "': %d\n", fd);
    close(fd);

    close(fd_cwd);
}

void test_read_write(void)
{
    int fd;
    long ret;
    char data[256]    = { 0 };
    const char text[] = "Hello, world!";

    fd  = open(TEST_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ret = syscall(SYS_write, fd, text, sizeof(text));
    printf("write '" TEST_FILE "': %ld\n", ret);
    close(fd);

    fd  = open(TEST_FILE, O_RDONLY);
    ret = syscall(SYS_read, fd, data, sizeof(data));
    printf("read  '" TEST_FILE "': %ld\n", ret);
    close(fd);

    printf(TEST_FILE ": %s\n", data);

    memset(data, 0, sizeof(data));

    fd  = open(HIDDEN_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ret = syscall(SYS_write, fd, text, sizeof(text));
    printf("write '" HIDDEN_FILE "': %ld\n", ret);
    close(fd);

    fd  = open(HIDDEN_FILE, O_RDONLY);
    ret = syscall(SYS_read, fd, data, sizeof(data));
    printf("read  '" HIDDEN_FILE "': %ld\n", ret);
    close(fd);

    printf(HIDDEN_FILE ": %s\n", data);
}

void test_stat(void)
{
    int fd_cwd;
    long ret;
    struct stat st;
    struct statx stx;

    fd_cwd = open(".", O_RDONLY | O_DIRECTORY | O_PATH);

    ret = syscall(SYS_stat, TEST_FILE, &st);
    printf("stat       '" TEST_FILE "': %ld\n", ret);

    ret = syscall(SYS_lstat, TEST_FILE, &st);
    printf("lstat      '" TEST_FILE "': %ld\n", ret);

    ret = syscall(SYS_newfstatat, fd_cwd, TEST_FILE, &st, 0);
    printf("newfstatat '" TEST_FILE "': %ld\n", ret);

    ret = syscall(SYS_statx, fd_cwd, TEST_FILE, 0, STATX_BASIC_STATS | STATX_BTIME, &stx);
    printf("statx      '" TEST_FILE "': %ld\n", ret);

    ret = syscall(SYS_stat, HIDDEN_FILE, &st);
    printf("stat       '" HIDDEN_FILE "': %ld\n", ret);

    ret = syscall(SYS_lstat, HIDDEN_FILE, &st);
    printf("lstat      '" HIDDEN_FILE "': %ld\n", ret);

    ret = syscall(SYS_newfstatat, fd_cwd, HIDDEN_FILE, &st, 0);
    printf("newfstatat '" HIDDEN_FILE "': %ld\n", ret);

    ret = syscall(SYS_statx, fd_cwd, HIDDEN_FILE, 0, STATX_BASIC_STATS | STATX_BTIME, &stx);
    printf("statx      '" HIDDEN_FILE "': %ld\n", ret);

    close(fd_cwd);
}

int main(void)
{
    test_open();
    putchar('\n');

    test_read_write();
    putchar('\n');

    test_stat();
    putchar('\n');

    return 0;
}
