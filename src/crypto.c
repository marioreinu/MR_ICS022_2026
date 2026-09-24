#include <string.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "crypto.h"

int crypto_random_bytes(unsigned char *buf, size_t len) {
    if (len == 0) {
        return 0;
    }
    if (buf == NULL) {
        return -1;
    }
    if (RAND_bytes(buf, (int)len) != 1) {
        return -1;
    }
    return 0;
}

int crypto_pbkdf2_sha256(const char *password,
                          const unsigned char *salt, size_t salt_len,
                          unsigned int iterations,
                          unsigned char *out, size_t out_len) {
    if (password == NULL || salt == NULL || out == NULL || out_len == 0 || iterations == 0) {
        return -1;
    }

    int ok = PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                                salt, (int)salt_len,
                                (int)iterations,
                                EVP_sha256(),
                                (int)out_len, out);
    return (ok == 1) ? 0 : -1;
}

int crypto_aes_gcm_encrypt(const unsigned char *key, size_t key_len,
                            const unsigned char *iv, size_t iv_len,
                            const unsigned char *plaintext, size_t plaintext_len,
                            unsigned char *ciphertext_out,
                            unsigned char *tag_out, size_t tag_len) {
    if (key == NULL || key_len != CRYPTO_AES_KEY_LEN) return -1;
    if (iv == NULL || iv_len == 0) return -1;
    if (tag_out == NULL || tag_len != CRYPTO_GCM_TAG_LEN) return -1;
    if (plaintext_len > 0 && (plaintext == NULL || ciphertext_out == NULL)) return -1;

    int ret = -1;
    int len = 0;
    int total_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext_out, &len, plaintext, (int)plaintext_len) != 1) goto done;
        total_len = len;
    }
    if (EVP_EncryptFinal_ex(ctx, ciphertext_out + total_len, &len) != 1) goto done;
    total_len += len;

    if ((size_t)total_len != plaintext_len) goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len, tag_out) != 1) goto done;

    ret = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int crypto_aes_gcm_decrypt(const unsigned char *key, size_t key_len,
                            const unsigned char *iv, size_t iv_len,
                            const unsigned char *ciphertext, size_t ciphertext_len,
                            const unsigned char *tag, size_t tag_len,
                            unsigned char *plaintext_out) {
    if (key == NULL || key_len != CRYPTO_AES_KEY_LEN) return -1;
    if (iv == NULL || iv_len == 0) return -1;
    if (tag == NULL || tag_len != CRYPTO_GCM_TAG_LEN) return -1;
    if (ciphertext_len > 0 && (ciphertext == NULL || plaintext_out == NULL)) return -1;

    int ret = -1;
    int len = 0;
    int total_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto done;

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext_out, &len, ciphertext, (int)ciphertext_len) != 1) goto done;
        total_len = len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void *)(size_t)tag) != 1) goto done;

    if (EVP_DecryptFinal_ex(ctx, plaintext_out + total_len, &len) != 1) {
        OPENSSL_cleanse(plaintext_out, ciphertext_len);
        goto done;
    }
    total_len += len;
    if ((size_t)total_len != ciphertext_len) {
        OPENSSL_cleanse(plaintext_out, ciphertext_len);
        goto done;
    }

    ret = 0;

done:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

void crypto_zero(void *buf, size_t len) {
    if (buf != NULL && len > 0) {
        OPENSSL_cleanse(buf, len);
    }
}
