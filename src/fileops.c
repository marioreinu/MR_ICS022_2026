#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "fileops.h"
#include "metadata.h"
#include "crypto.h"
#include "logging.h"

#define FILEOPS_STORAGE_DIR "storage"
#define FILEOPS_MAX_FILE_SIZE (64u * 1024u * 1024u) /* 64 MB */
#define FILEOPS_HEADER_LEN (CRYPTO_GCM_IV_LEN + CRYPTO_GCM_TAG_LEN)
#define FILEOPS_STORAGE_PATH_MAX (sizeof(FILEOPS_STORAGE_DIR) + 1 + METADATA_FILE_ID_LEN + 4 + 1)
#define FILEOPS_NFD_BUF_LEN (FILEOPS_NAME_MAX * 2)
#define FILEOPS_RESOLVED_PATH_MAX 1024

static int build_storage_path(const char *file_id, char *out, size_t out_size) {
    int n = snprintf(out, out_size, "%s/%s.sfm", FILEOPS_STORAGE_DIR, file_id);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
}

typedef struct {
    unsigned char precomposed_byte2;
    char base;
    unsigned char mark_byte2;
} nfd_decomposition_t;

static const nfd_decomposition_t NFD_TABLE[] = {
    {0x80, 'A', 0x80}, {0x81, 'A', 0x81}, {0x82, 'A', 0x82}, {0x83, 'A', 0x83},
    {0x84, 'A', 0x88}, {0x85, 'A', 0x8A}, {0x87, 'C', 0xA7},
    {0x88, 'E', 0x80}, {0x89, 'E', 0x81}, {0x8A, 'E', 0x82}, {0x8B, 'E', 0x88},
    {0x8C, 'I', 0x80}, {0x8D, 'I', 0x81}, {0x8E, 'I', 0x82}, {0x8F, 'I', 0x88},
    {0x91, 'N', 0x83},
    {0x92, 'O', 0x80}, {0x93, 'O', 0x81}, {0x94, 'O', 0x82}, {0x95, 'O', 0x83}, {0x96, 'O', 0x88},
    {0x99, 'U', 0x80}, {0x9A, 'U', 0x81}, {0x9B, 'U', 0x82}, {0x9C, 'U', 0x88},
    {0x9D, 'Y', 0x81},
    {0xA0, 'a', 0x80}, {0xA1, 'a', 0x81}, {0xA2, 'a', 0x82}, {0xA3, 'a', 0x83},
    {0xA4, 'a', 0x88}, {0xA5, 'a', 0x8A}, {0xA7, 'c', 0xA7},
    {0xA8, 'e', 0x80}, {0xA9, 'e', 0x81}, {0xAA, 'e', 0x82}, {0xAB, 'e', 0x88},
    {0xAC, 'i', 0x80}, {0xAD, 'i', 0x81}, {0xAE, 'i', 0x82}, {0xAF, 'i', 0x88},
    {0xB1, 'n', 0x83},
    {0xB2, 'o', 0x80}, {0xB3, 'o', 0x81}, {0xB4, 'o', 0x82}, {0xB5, 'o', 0x83}, {0xB6, 'o', 0x88},
    {0xB9, 'u', 0x80}, {0xBA, 'u', 0x81}, {0xBB, 'u', 0x82}, {0xBC, 'u', 0x88},
    {0xBD, 'y', 0x81},
};
#define NFD_TABLE_LEN (sizeof(NFD_TABLE) / sizeof(NFD_TABLE[0]))

static int to_nfd_fallback(const char *path, char *out, size_t out_size) {
    size_t in_len = strlen(path);
    size_t oi = 0;

    for (size_t i = 0; i < in_len; ) {
        unsigned char c = (unsigned char)path[i];
        int replaced = 0;

        if (c == 0xC3 && i + 1 < in_len) {
            unsigned char b2 = (unsigned char)path[i + 1];
            for (size_t t = 0; t < NFD_TABLE_LEN; t++) {
                if (NFD_TABLE[t].precomposed_byte2 == b2) {
                    if (oi + 3 >= out_size) {
                        return -1;
                    }
                    out[oi++] = NFD_TABLE[t].base;
                    out[oi++] = (char)0xCC;
                    out[oi++] = (char)NFD_TABLE[t].mark_byte2;
                    i += 2;
                    replaced = 1;
                    break;
                }
            }
        }

        if (!replaced) {
            if (oi + 1 >= out_size) {
                return -1;
            }
            out[oi++] = path[i];
            i += 1;
        }
    }
    out[oi] = '\0';
    return 0;
}

static FILE *secure_fopen_noflink(const char *path, const char *mode) {
    int flags;

    if (strcmp(mode, "rb") == 0) {
        flags = O_RDONLY | O_NOFOLLOW;
    } else if (strcmp(mode, "r+b") == 0) {
        flags = O_RDWR | O_NOFOLLOW;
    } else {
        return NULL; /* unsupported mode for this helper */
    }

    int fd = open(path, flags);
    if (fd < 0) {
        return NULL;
    }

    FILE *fp = fdopen(fd, mode);
    if (fp == NULL) {
        close(fd);
    }
    return fp;
}

static FILE *fopen_with_nfd_fallback_resolved(const char *path, const char *mode,
                                               char *resolved_out, size_t resolved_size) {
    FILE *fp = secure_fopen_noflink(path, mode);
    if (fp != NULL) {
        if (resolved_out != NULL) {
            snprintf(resolved_out, resolved_size, "%s", path);
        }
        return fp;
    }

    char nfd_path[FILEOPS_NFD_BUF_LEN];
    if (to_nfd_fallback(path, nfd_path, sizeof(nfd_path)) != 0) {
        return NULL;
    }
    if (strcmp(nfd_path, path) == 0) {
        return NULL;
    }
    fp = secure_fopen_noflink(nfd_path, mode);
    if (fp != NULL && resolved_out != NULL) {
        snprintf(resolved_out, resolved_size, "%s", nfd_path);
    }
    return fp;
}

static int read_whole_file_resolved(const char *path, unsigned char **out_buf, size_t *out_len,
                                     char *resolved_out, size_t resolved_size) {
    FILE *fp = fopen_with_nfd_fallback_resolved(path, "rb", resolved_out, resolved_size);
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long size = ftell(fp);
    if (size < 0 || (size_t)size > FILEOPS_MAX_FILE_SIZE) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    size_t len = (size_t)size;
    unsigned char *buf = malloc(len > 0 ? len : 1);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }

    size_t read_bytes = (len > 0) ? fread(buf, 1, len, fp) : 0;
    fclose(fp);
    if (read_bytes != len) {
        free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_len = len;
    return 0;
}

static int read_whole_file(const char *path, unsigned char **out_buf, size_t *out_len) {
    return read_whole_file_resolved(path, out_buf, out_len, NULL, 0);
}

static int overwrite_with_zeros(const char *path) {
    FILE *fp = secure_fopen_noflink(path, "r+b");
    if (fp == NULL) {
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long size = ftell(fp);
    if (size < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    unsigned char zeros[4096];
    memset(zeros, 0, sizeof(zeros));
    size_t remaining = (size_t)size;
    int ok = 1;
    while (remaining > 0 && ok) {
        size_t chunk = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
        if (fwrite(zeros, 1, chunk, fp) != chunk) {
            ok = 0;
        }
        remaining -= chunk;
    }
    fflush(fp);
    fclose(fp);
    return ok ? 0 : -1;
}

int fileops_encrypt(const char *username, const unsigned char *key, size_t key_len,
                     const char *input_path) {
    if (username == NULL || key == NULL || key_len != CRYPTO_AES_KEY_LEN || input_path == NULL) {
        return -1;
    }

    int result = -1;
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    unsigned char *ciphertext = NULL;
    FILE *out_fp = NULL;
    char storage_path[FILEOPS_STORAGE_PATH_MAX];
    unsigned char iv[CRYPTO_GCM_IV_LEN];
    unsigned char tag[CRYPTO_GCM_TAG_LEN];
    metadata_record_t record;
    int storage_file_created = 0;
    char original_resolved_path[FILEOPS_RESOLVED_PATH_MAX];

    memset(&record, 0, sizeof(record));
    storage_path[0] = '\0';
    original_resolved_path[0] = '\0';

    if (read_whole_file_resolved(input_path, &plaintext, &plaintext_len,
                                  original_resolved_path, sizeof(original_resolved_path)) != 0) {
        goto cleanup;
    }

    {
        const char *base = strrchr(input_path, '/');
        base = (base != NULL) ? base + 1 : input_path;
        strncpy(record.owner, username, sizeof(record.owner) - 1);
        strncpy(record.stored_name, base, sizeof(record.stored_name) - 1);
        record.created_at = time(NULL);
    }

    if (metadata_generate_file_id(record.file_id, sizeof(record.file_id)) != 0) {
        goto cleanup;
    }
    if (crypto_random_bytes(iv, sizeof(iv)) != 0) {
        goto cleanup;
    }

    ciphertext = malloc(plaintext_len > 0 ? plaintext_len : 1);
    if (ciphertext == NULL) {
        goto cleanup;
    }

    if (crypto_aes_gcm_encrypt(key, key_len, iv, sizeof(iv),
                                plaintext, plaintext_len,
                                ciphertext, tag, sizeof(tag)) != 0) {
        goto cleanup;
    }

    if (build_storage_path(record.file_id, storage_path, sizeof(storage_path)) != 0) {
        goto cleanup;
    }

    out_fp = fopen(storage_path, "wxb");
    if (out_fp == NULL) {
        goto cleanup;
    }
    storage_file_created = 1;
    if (chmod(storage_path, S_IRUSR | S_IWUSR) != 0) {
        goto cleanup;
    }

    if (fwrite(iv, 1, sizeof(iv), out_fp) != sizeof(iv)) goto cleanup;
    if (fwrite(tag, 1, sizeof(tag), out_fp) != sizeof(tag)) goto cleanup;
    if (plaintext_len > 0 && fwrite(ciphertext, 1, plaintext_len, out_fp) != plaintext_len) {
        goto cleanup;
    }
    fclose(out_fp);
    out_fp = NULL;

    if (metadata_create(&record) != 0) {

        remove(storage_path);
        storage_file_created = 0;
        goto cleanup;
    }

    result = 0;

    overwrite_with_zeros(original_resolved_path);
    remove(original_resolved_path);

cleanup:
    if (out_fp != NULL) {
        fclose(out_fp);
    }
    if (result != 0 && storage_file_created) {
        remove(storage_path);
    }
    if (plaintext != NULL) {
        crypto_zero(plaintext, plaintext_len);
        free(plaintext);
    }
    if (ciphertext != NULL) {
        free(ciphertext);
    }
    logging_event("ENCRYPT_FILE", username, "fileops", result == 0 ? "success" : "failure");
    return result;
}

int fileops_decrypt(const char *username, const unsigned char *key, size_t key_len,
                     const char *stored_name, const char *output_path) {
    if (username == NULL || key == NULL || key_len != CRYPTO_AES_KEY_LEN
        || stored_name == NULL || output_path == NULL) {
        return -1;
    }

    int result = -1;
    unsigned char *file_buf = NULL;
    size_t file_len = 0;
    unsigned char *plaintext = NULL;
    size_t ciphertext_len = 0;
    FILE *out_fp = NULL;
    char storage_path[FILEOPS_STORAGE_PATH_MAX];
    metadata_record_t record;

    if (metadata_load(username, stored_name, &record) != 0) {
        goto cleanup;
    }
    if (build_storage_path(record.file_id, storage_path, sizeof(storage_path)) != 0) {
        goto cleanup;
    }
    if (read_whole_file(storage_path, &file_buf, &file_len) != 0) {
        goto cleanup;
    }
    if (file_len < FILEOPS_HEADER_LEN) {
        goto cleanup; 
    }

    {
        const unsigned char *iv = file_buf;
        const unsigned char *tag = file_buf + CRYPTO_GCM_IV_LEN;
        const unsigned char *ciphertext = file_buf + FILEOPS_HEADER_LEN;
        ciphertext_len = file_len - FILEOPS_HEADER_LEN;

        plaintext = malloc(ciphertext_len > 0 ? ciphertext_len : 1);
        if (plaintext == NULL) {
            goto cleanup;
        }

        if (crypto_aes_gcm_decrypt(key, key_len, iv, CRYPTO_GCM_IV_LEN,
                                    ciphertext, ciphertext_len,
                                    tag, CRYPTO_GCM_TAG_LEN, plaintext) != 0) {
            goto cleanup;
        }
    }

    out_fp = fopen(output_path, "wxb");
    if (out_fp == NULL) {
        goto cleanup;
    }
    if (ciphertext_len > 0 && fwrite(plaintext, 1, ciphertext_len, out_fp) != ciphertext_len) {
        goto cleanup;
    }
    fclose(out_fp);
    out_fp = NULL;

    result = 0;

cleanup:
    if (out_fp != NULL) {
        fclose(out_fp);
    }
    if (plaintext != NULL) {
        crypto_zero(plaintext, ciphertext_len);
        free(plaintext);
    }
    if (file_buf != NULL) {
        crypto_zero(file_buf, file_len);
        free(file_buf);
    }
    logging_event("DECRYPT_FILE", username, "fileops", result == 0 ? "success" : "failure");
    return result;
}

int fileops_delete(const char *username, const char *stored_name) {
    if (username == NULL || stored_name == NULL) {
        return -1;
    }

    int result = -1;
    metadata_record_t record;
    char storage_path[FILEOPS_STORAGE_PATH_MAX];

    if (metadata_load(username, stored_name, &record) != 0) {
        goto done;
    }
    if (build_storage_path(record.file_id, storage_path, sizeof(storage_path)) != 0) {
        goto done;
    }

    overwrite_with_zeros(storage_path);

    {
        int storage_ok = (remove(storage_path) == 0);
        int metadata_ok = (metadata_delete(username, stored_name) == 0);
        result = (storage_ok && metadata_ok) ? 0 : -1;
    }

done:
    logging_event("DELETE_FILE", username, "fileops", result == 0 ? "success" : "failure");
    return result;
}

static void list_print_callback(const metadata_record_t *record, void *user_data) {
    int *count = (int *)user_data;
    (*count)++;
    printf("  %s\n", record->stored_name);
}

int fileops_list(const char *username) {
    if (username == NULL) {
        return -1;
    }

    int count = 0;
    int result = (metadata_list(username, list_print_callback, &count) == 0) ? 0 : -1;
    if (result == 0 && count == 0) {
        printf("  (No files found)\n");
    }
    logging_event("LIST_FILES", username, "fileops", result == 0 ? "success" : "failure");
    return result;
}