#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#define AUTH_USERNAME_MAX 64

#define AUTH_PASSWORD_MAX 128

#define AUTH_MASTER_KEY_LEN 32

int auth_login(const char *username, const char *password,
                char *out_username, size_t out_size,
                unsigned char *out_master_key, size_t out_master_key_len);


int auth_create_user(const char *username, const char *password);


int auth_admin_login(const char *username, const char *password,
                      char *out_username, size_t out_size,
                      unsigned char *out_master_key, size_t out_master_key_len);

#endif 
