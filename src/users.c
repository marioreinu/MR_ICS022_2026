#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

#include "users.h"

#define USERS_DIR "users"
#define USERS_PATH_MAX (sizeof(USERS_DIR) + 1 + AUTH_USERNAME_MAX + 4)

int users_username_is_safe(const char *username) {
    if (username == NULL) {
        return 0;
    }
    size_t len = strlen(username);
    if (len == 0 || len >= AUTH_USERNAME_MAX) {
        return 0;
    }
    if (username[0] == '.') {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)username[i];
        if (!(isalnum(c) || c == '_' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

static int build_path(const char *username, char *out, size_t out_size) {
    int n = snprintf(out, out_size, "%s/%s.rec", USERS_DIR, username);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
}

int users_exists(const char *username) {
    if (!users_username_is_safe(username)) {
        return 0;
    }
    char path[USERS_PATH_MAX];
    if (build_path(username, path, sizeof(path)) != 0) {
        return 0;
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return 0;
    }
    fclose(fp);
    return 1;
}

static int write_record(FILE *fp, const user_record_t *record) {
    char name_buf[AUTH_USERNAME_MAX];
    memset(name_buf, 0, sizeof(name_buf));
    strncpy(name_buf, record->username, sizeof(name_buf) - 1);

    uint8_t role_byte = (uint8_t)record->role;
    uint32_t iterations = (uint32_t)record->iterations;

    if (fwrite(name_buf, 1, sizeof(name_buf), fp) != sizeof(name_buf)) return -1;
    if (fwrite(&role_byte, 1, sizeof(role_byte), fp) != sizeof(role_byte)) return -1;
    if (fwrite(&iterations, 1, sizeof(iterations), fp) != sizeof(iterations)) return -1;
    if (fwrite(record->auth_salt, 1, USERS_SALT_LEN, fp) != USERS_SALT_LEN) return -1;
    if (fwrite(record->auth_hash, 1, USERS_HASH_LEN, fp) != USERS_HASH_LEN) return -1;
    if (fwrite(record->enc_salt, 1, USERS_SALT_LEN, fp) != USERS_SALT_LEN) return -1;
    return 0;
}

static int read_record(FILE *fp, user_record_t *record) {
    char name_buf[AUTH_USERNAME_MAX];
    uint8_t role_byte;
    uint32_t iterations;

    if (fread(name_buf, 1, sizeof(name_buf), fp) != sizeof(name_buf)) return -1;
    if (fread(&role_byte, 1, sizeof(role_byte), fp) != sizeof(role_byte)) return -1;
    if (fread(&iterations, 1, sizeof(iterations), fp) != sizeof(iterations)) return -1;
    if (fread(record->auth_salt, 1, USERS_SALT_LEN, fp) != USERS_SALT_LEN) return -1;
    if (fread(record->auth_hash, 1, USERS_HASH_LEN, fp) != USERS_HASH_LEN) return -1;
    if (fread(record->enc_salt, 1, USERS_SALT_LEN, fp) != USERS_SALT_LEN) return -1;

    name_buf[sizeof(name_buf) - 1] = '\0';
    memcpy(record->username, name_buf, sizeof(record->username));
    record->role = (role_byte == (uint8_t)USER_ROLE_ADMIN) ? USER_ROLE_ADMIN : USER_ROLE_STANDARD;
    record->iterations = iterations;
    return 0;
}

int users_load(const char *username, user_record_t *out_record) {
    if (!users_username_is_safe(username) || out_record == NULL) {
        return -1;
    }
    char path[USERS_PATH_MAX];
    if (build_path(username, path, sizeof(path)) != 0) {
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    int result = read_record(fp, out_record);
    fclose(fp);
    return result;
}

int users_create(const user_record_t *record) {
    if (record == NULL || !users_username_is_safe(record->username)) {
        return -1;
    }
    char path[USERS_PATH_MAX];
    if (build_path(record->username, path, sizeof(path)) != 0) {
        return -1;
    }

    FILE *fp = fopen(path, "wxb");
    if (fp == NULL) {
        return -1;
    }

    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        fclose(fp);
        remove(path);
        return -1;
    }

    int result = write_record(fp, record);
    fclose(fp);
    if (result != 0) {
        remove(path);
    }
    return result;
}

int users_admin_exists(void) {
    DIR *dir = opendir(USERS_DIR);
    if (dir == NULL) {
        return -1;
    }

    int found = 0;
    struct dirent *entry;
    static const char suffix[] = ".rec";
    size_t suffix_len = sizeof(suffix) - 1;

    while (!found && (entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t name_len = strlen(name);
        if (name_len <= suffix_len || strcmp(name + name_len - suffix_len, suffix) != 0) {
            continue;
        }

        char path[USERS_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", USERS_DIR, name);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            continue;
        }

        FILE *fp = fopen(path, "rb");
        if (fp == NULL) {
            continue;
        }
        user_record_t record;
        int rc = read_record(fp, &record);
        fclose(fp);

        if (rc == 0 && record.role == USER_ROLE_ADMIN) {
            found = 1;
        }
    }

    closedir(dir);
    return found;
}

int users_list(users_list_callback_t callback, void *user_data) {
    if (callback == NULL) {
        return -1;
    }

    DIR *dir = opendir(USERS_DIR);
    if (dir == NULL) {
        return -1;
    }

    struct dirent *entry;
    static const char suffix[] = ".rec";
    size_t suffix_len = sizeof(suffix) - 1;

    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t name_len = strlen(name);
        if (name_len <= suffix_len || strcmp(name + name_len - suffix_len, suffix) != 0) {
            continue;
        }

        char path[USERS_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", USERS_DIR, name);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            continue; /* shouldn't happen for a name readdir() gave us, but skip rather than fail the whole scan */
        }

        FILE *fp = fopen(path, "rb");
        if (fp == NULL) {
            continue; /* one unreadable record shouldn't hide the rest */
        }
        user_record_t record;
        int rc = read_record(fp, &record);
        fclose(fp);

        if (rc == 0) {
            callback(&record, user_data);
        }
    }

    closedir(dir);
    return 0;
}