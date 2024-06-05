# pragma once

#include <string.h>
#include <pthread.h>

#define MAX_BUF 1024
#define MAX_LEN 10

typedef struct {
    int idx;
    char key[MAX_LEN][MAX_BUF];
    char value[MAX_LEN][MAX_BUF];
} Redis;

int init(Redis *redis);
int isfull(Redis *redis);
int isempty(Redis *redis);
int findkey(Redis *redis, char *_key);
int set(Redis *redis, char *_key, char *_value);
int get(Redis *redis, char *_key, char *a);