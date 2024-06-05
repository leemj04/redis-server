#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "redis.h"

#define BUF_SIZE 1024
#define MAX_CLIENT 10

void usage() {
    printf("Usage  : ./server [port]\n");
    printf("Example: ./server 12345\n");

}

Redis redis;

void client_connect(void *sd) {
    int client_socket = *(int *)sd;
    char recvbuf[BUF_SIZE], sendbuf[BUF_SIZE + 50];
    int len, res, ck;

    printf("connected client\n");

    while(1) {
        len = recv(client_socket, recvbuf, BUF_SIZE, 0);

        if (len == 0 || len == -1) {
            break;
        }

        char *method = strtok(recvbuf, " ");
        if(strcmp(method, "set") == 0) {
            char *key = strtok(NULL, " ");
            char *value = strtok(NULL, "\r\n");

            if (key == NULL || value == NULL) {
                strcpy(sendbuf, "Invalid command\r\n");
            } else {
                ck = set(&redis, key, value);

                if(ck == -1) {
                    strcpy(sendbuf, "Redis is full\r\n");
                } else {
                    strcpy(sendbuf, "+OK\r\n");
                }
            }

        } else if(strcmp(method, "get") == 0) {
            char *key = strtok(NULL, "\r\n");
            ck = get(&redis, key, recvbuf);

            if(ck == -1) {
                strcpy(sendbuf, "$-1\r\n");
            } else {
                snprintf(sendbuf, BUF_SIZE + 50, "$%d\r\n%s\r\n", ck, recvbuf);
            }
            
        } else {
            strcpy(sendbuf, "Invalid command\r\n");
        }

        res = send(client_socket, sendbuf, strlen(sendbuf), 0);

        if (res == 0 || res == -1) {
            break;
        }
    }

    printf("disconnected client\r\n");
    close(client_socket);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage();
        return 0;
    }

    init(&redis);

    int port = atoi(argv[1]);
    int server_socket;
    int client_socket;
    int client_addr_size;

    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    char buf[BUF_SIZE];
    int len, res;

    pthread_t thread;

    server_socket = socket(PF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        printf("socket() error\n");
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("bind() error\n");
        return 0;
    }

    if (listen(server_socket, 5) == -1) {
        printf("listen() error\n");
        return 0;
    }

    client_addr_size = sizeof(client_addr);

    while(1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_size);
        if (client_socket == -1) {
            printf("accept() error\n");
            return 0;
        }
        
        pthread_create(&thread, NULL, (void *)&client_connect, (void *)&client_socket);
        pthread_detach(thread);
    }

    close(server_socket);

    return 0;
}