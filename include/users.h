#ifndef USERS_H
#define USERS_H

#include <stddef.h>
#include "auth.h"

#define USERS_SALT_LEN 16
#define USERS_HASH_LEN 32

typedef enum {
    USER_ROLE_STANDARD = 0,
    USER_ROLE_ADMIN = 1
} user_role_t;

typedef struct {
    char username[AUTH_USERNAME_MAX];
    user_role_t role;
    unsigned int iterations;
    unsigned char auth_salt[USERS_SALT_LEN];  
    unsigned char auth_hash[USERS_HASH_LEN];
    unsigned char enc_salt[USERS_SALT_LEN]; 
} user_record_t;

int users_username_is_safe(const char *username);

int users_exists(const char *username);

int users_load(const char *username, user_record_t *out_record);

int users_create(const user_record_t *record);

#endif
