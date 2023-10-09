#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    int fd;
    char data[256];
    const char text[] = "Hello, world!\n";

    fd = open("test.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, text, sizeof(text));
    close(fd);

    fd = open("test.txt", O_RDONLY);
    read(fd, data, sizeof(data));
    close(fd);

    return 0;
}
