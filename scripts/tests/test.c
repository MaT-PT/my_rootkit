#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_FILE   "test.txt"
#define HIDDEN_FILE ".rootkit_test"

void test_stat()
{
    int fd   = -1;
    long ret = 0;
    struct stat st;
    struct statx stx;

    fd = open(".", O_RDONLY | O_DIRECTORY | O_PATH);

    ret = syscall(SYS_stat, TEST_FILE, &st);
    printf("stat       '" TEST_FILE "': %ld\n", ret);

    ret = syscall(SYS_lstat, TEST_FILE, &st);
    printf("lstat      '" TEST_FILE "': %ld\n", ret);

    ret = syscall(SYS_newfstatat, fd, TEST_FILE, &st, 0);
    printf("newfstatat '" TEST_FILE "': %ld\n", ret);

    ret = syscall(SYS_statx, fd, TEST_FILE, 0, STATX_BASIC_STATS | STATX_BTIME, &stx);
    printf("statx      '" TEST_FILE "': %ld\n", ret);

    ret = syscall(SYS_stat, HIDDEN_FILE, &st);
    printf("stat       '" HIDDEN_FILE "': %ld\n", ret);

    ret = syscall(SYS_lstat, HIDDEN_FILE, &st);
    printf("lstat      '" HIDDEN_FILE "': %ld\n", ret);

    ret = syscall(SYS_newfstatat, fd, HIDDEN_FILE, &st, 0);
    printf("newfstatat '" HIDDEN_FILE "': %ld\n", ret);

    ret = syscall(SYS_statx, fd, HIDDEN_FILE, 0, STATX_BASIC_STATS | STATX_BTIME, &stx);
    printf("statx      '" HIDDEN_FILE "': %ld\n", ret);

    close(fd);
}

int main()
{
    int fd;
    char data[256];
    const char text[] = "Hello, world!\n";

    fd = open("test.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, text, sizeof(text));
    close(fd);

    fd = open("test.txt", O_RDONLY);
    read(fd, data, sizeof(data));
    close(fd);

    printf("%s", data);

    test_stat();

    return 0;
}
