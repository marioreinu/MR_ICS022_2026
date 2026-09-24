#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

#include "metadata.h"
#include "crypto.h"

#define METADATA_DIR "metadata"
#define METADATA_PATH_MAX (sizeof(METADATA_DIR) + 1 + AUTH_USERNAME_MAX + 2 + FILEOPS_NAME_MAX + 4)

static int owner_is_safe(const char *owner) {
    if (owner == NULL) {
        return 0;
    }
    size_t len = strlen(owner);
    if (len == 0 || len >= AUTH_USERNAME_MAX) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)owner[i];
        if (!(isalnum(c) || c == '_' || c == '-')) {
            return 0;
        }
    }
    return 1;
}

static int stored_name_is_safe(const char *name) {
    if (name == NULL) {
        return 0;
    }
    size_t len = strlen(name);
    if (len == 0 || len >= FILEOPS_NAME_MAX) {
        return 0;
    }
    if (name[0] == '.') {
        return 0;
    }
    if (strstr(name, "..") != NULL) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.')) {
            return 0;
        }
    }
    return 1;
}

static int build_path(const char *owner, const char *stored_name, char *out, size_t out_size) {
    int n = snprintf(out, out_size, "%s/%s__%s.rec", METADATA_DIR, owner, stored_name);
    if (n < 0 || (size_t)n >= out_size) {
        return -1;
    }
    return 0;
}

int metadata_generate_file_id(char *out, size_t out_size) {
    if (out == NULL || out_size < (size_t)METADATA_FILE_ID_LEN + 1) {
        return -1;
    }

    unsigned char raw[METADATA_FILE_ID_LEN / 2]; /* 16 bytes -> 32 hex chars */
    if (crypto_random_bytes(raw, sizeof(raw)) != 0) {
        return -1;
    }

    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(raw); i++) {
        out[i * 2]     = hex[(raw[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[raw[i] & 0x0F];
    }
    out[METADATA_FILE_ID_LEN] = '\0';
    return 0;
}

static int write_record(FILE *fp, const metadata_record_t *record) {
    char owner_buf[AUTH_USERNAME_MAX];
    char name_buf[FILEOPS_NAME_MAX];
    char id_buf[METADATA_FILE_ID_LEN + 1];
    int64_t created_at = (int64_t)record->created_at;

    memset(owner_buf, 0, sizeof(owner_buf));
    memset(name_buf, 0, sizeof(name_buf));
    memset(id_buf, 0, sizeof(id_buf));
    strncpy(owner_buf, record->owner, sizeof(owner_buf) - 1);
    strncpy(name_buf, record->stored_name, sizeof(name_buf) - 1);
    strncpy(id_buf, record->file_id, sizeof(id_buf) - 1);

    if (fwrite(owner_buf, 1, sizeof(owner_buf), fp) != sizeof(owner_buf)) return -1;
    if (fwrite(name_buf, 1, sizeof(name_buf), fp) != sizeof(name_buf)) return -1;
    if (fwrite(id_buf, 1, sizeof(id_buf), fp) != sizeof(id_buf)) return -1;
    if (fwrite(&created_at, 1, sizeof(created_at), fp) != sizeof(created_at)) return -1;
    return 0;
}

static int read_record(FILE *fp, metadata_record_t *record) {
    char owner_buf[AUTH_USERNAME_MAX];
    char name_buf[FILEOPS_NAME_MAX];
    char id_buf[METADATA_FILE_ID_LEN + 1];
    int64_t created_at;

    if (fread(owner_buf, 1, sizeof(owner_buf), fp) != sizeof(owner_buf)) return -1;
    if (fread(name_buf, 1, sizeof(name_buf), fp) != sizeof(name_buf)) return -1;
    if (fread(id_buf, 1, sizeof(id_buf), fp) != sizeof(id_buf)) return -1;
    if (fread(&created_at, 1, sizeof(created_at), fp) != sizeof(created_at)) return -1;

    owner_buf[sizeof(owner_buf) - 1] = '\0';
    name_buf[sizeof(name_buf) - 1] = '\0';
    id_buf[sizeof(id_buf) - 1] = '\0';

    memcpy(record->owner, owner_buf, sizeof(record->owner));
    memcpy(record->stored_name, name_buf, sizeof(record->stored_name));
    memcpy(record->file_id, id_buf, sizeof(record->file_id));
    record->created_at = (time_t)created_at;
    return 0;
}

int metadata_create(const metadata_record_t *record) {
    if (record == NULL || !owner_is_safe(record->owner) || !stored_name_is_safe(record->stored_name)) {
        return -1;
    }
    char path[METADATA_PATH_MAX];
    if (build_path(record->owner, record->stored_name, path, sizeof(path)) != 0) {
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

int metadata_load(const char *owner, const char *stored_name, metadata_record_t *out_record) {
    if (!owner_is_safe(owner) || !stored_name_is_safe(stored_name) || out_record == NULL) {
        return -1;
    }
    char path[METADATA_PATH_MAX];
    if (build_path(owner, stored_name, path, sizeof(path)) != 0) {
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }
    int result = read_record(fp, out_record);
    fclose(fp);
    if (result != 0) {
        return -1;
    }
    if (strcmp(out_record->owner, owner) != 0 || strcmp(out_record->stored_name, stored_name) != 0) {
        return -1;
    }
    return 0;
}

int metadata_delete(const char *owner, const char *stored_name) {
    if (!owner_is_safe(owner) || !stored_name_is_safe(stored_name)) {
        return -1;
    }
    char path[METADATA_PATH_MAX];
    if (build_path(owner, stored_name, path, sizeof(path)) != 0) {
        return -1;
    }

    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1; /* nothing to delete */
    }
    fclose(fp);

    return (remove(path) == 0) ? 0 : -1;
}

int metadata_list(const char *owner, metadata_list_callback callback, void *user_data) {
    if (!owner_is_safe(owner) || callback == NULL) {
        return -1;
    }

    DIR *dir = opendir(METADATA_DIR);
    if (dir == NULL) {
        return -1;
    }

    char prefix[AUTH_USERNAME_MAX + 2];
    int pn = snprintf(prefix, sizeof(prefix), "%s__", owner);
    if (pn < 0 || (size_t)pn >= sizeof(prefix)) {
        closedir(dir);
        return -1;
    }
    size_t prefix_len = strlen(prefix);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t name_len = strlen(name);

        if (name_len <= prefix_len || strncmp(name, prefix, prefix_len) != 0) {
            continue;
        }
        static const char suffix[] = ".rec";
        size_t suffix_len = sizeof(suffix) - 1;
        if (name_len <= suffix_len || strcmp(name + name_len - suffix_len, suffix) != 0) {
            continue;
        }

        char path[METADATA_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", METADATA_DIR, name);
        if (n < 0 || (size_t)n >= sizeof(path)) {
            continue;
        }

        FILE *fp = fopen(path, "rb");
        if (fp == NULL) {
            continue;
        }
        metadata_record_t record;
        int rc = read_record(fp, &record);
        fclose(fp);

        if (rc == 0 && strcmp(record.owner, owner) == 0) {
            callback(&record, user_data);
        }
    }

    closedir(dir);
    return 0;
}
