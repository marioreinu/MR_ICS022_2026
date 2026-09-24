#ifndef FILEOPS_H
#define FILEOPS_H

#include <stddef.h>

#define FILEOPS_NAME_MAX 256


int fileops_encrypt(const char *username, const unsigned char *key, size_t key_len,
                     const char *input_path);


int fileops_decrypt(const char *username, const unsigned char *key, size_t key_len,
                     const char *stored_name, const char *output_path);


int fileops_delete(const char *username, const char *stored_name);


int fileops_list(const char *username);

#endif
