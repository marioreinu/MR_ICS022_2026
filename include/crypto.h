#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

int crypto_random_bytes(unsigned char *buf, size_t len);

int crypto_pbkdf2_sha256(const char *password,
                          const unsigned char *salt, size_t salt_len,
                          unsigned int iterations,
                          unsigned char *out, size_t out_len);

#define CRYPTO_AES_KEY_LEN 32 
#define CRYPTO_GCM_IV_LEN 12
#define CRYPTO_GCM_TAG_LEN 16

int crypto_aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                            const unsigned char *iv, size_t iv_len,
                            const unsigned char *plaintext, size_t plaintext_len,
                            unsigned char *ciphertext_out,
                            unsigned char *tag_out, size_t tag_len);

int crypto_aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                            const unsigned char *iv, size_t iv_len,
                            const unsigned char *ciphertext, size_t ciphertext_len,
                            const unsigned char *tag, size_t tag_len,
                            unsigned char *plaintext_out);


void crypto_zero(void *buf, size_t len);

#endif
