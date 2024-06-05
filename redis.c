#include "redis.h"

pthread_mutex_t lock;

int init(Redis *redis) {
    redis->idx = -1;
    pthread_mutex_init(&lock, NULL);
    return 0;
}

int isfull(Redis *redis) {
    return redis->idx == MAX_LEN - 1;
}

int isempty(Redis *redis) {
    return redis->idx == -1;
}

int findkey(Redis *redis, char *_key) {
    for (int i = 0; i <= redis->idx; i++) {
        if (strcmp(redis->key[i], _key) == 0) {
            return i;
        }
    }

    return redis->idx + 1;
}

int set(Redis *redis, char *_key, char *_value) {
    if (isfull(redis) && findkey(redis, _key) == MAX_LEN) {
        return -1;
    }

    pthread_mutex_lock(&lock);

    redis->idx = findkey(redis, _key);
    strncpy(redis->key[redis->idx], _key, strlen(_key));
    redis->key[redis->idx][strlen(_key)] = '\0';
    strncpy(redis->value[redis->idx], _value, strlen(_value));
    redis->value[redis->idx][strlen(_value)] = '\0';

    pthread_mutex_unlock(&lock);

    return 0;
}

int get(Redis *redis, char *_key, char *a) {
    if (isempty(redis)) {
        return -1;
    }

    for (int i = 0; i <= redis->idx; i++) {
        if (strcmp(redis->key[i], _key) == 0) {
            strcpy(a, redis->value[i]);
            return strlen(a);
        }
    }

    return -1;
}