#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUF_SIZE 1024

void usage() {
    printf("Usage  : ./client [ip] [port]\n");
    printf("Example: ./client 127.0.0.1 12345\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        usage();
        return 0;
    }

    int port = atoi(argv[2]);
    int client_socket;

    struct sockaddr_in server_addr;

    char buf[BUF_SIZE];
    int len;

    client_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        printf("socket() error");
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(argv[1]);

    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("connect() error");
        return 0;
    }

    while (1) {
        fgets(buf, sizeof(buf), stdin);

        if (strcmp(buf, "EXIT\n") == 0) {
            break;
        }

        send(client_socket, buf, strlen(buf), 0);
        len = recv(client_socket, buf, BUF_SIZE, 0);
        buf[len] = 0;
        printf("%s", buf);
    }

    close(client_socket);

    return 0;
}