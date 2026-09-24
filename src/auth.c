#include <string.h>

#include <openssl/crypto.h>

#include "auth.h"
#include "users.h"
#include "crypto.h"
#include "logging.h"


#define AUTH_PBKDF2_ITERATIONS 210000u

static int verify_password(const char *password, const user_record_t *record) {
    unsigned char computed[USERS_HASH_LEN];

    if (crypto_pbkdf2_sha256(password, record->auth_salt, USERS_SALT_LEN,
                              record->iterations, computed, sizeof(computed)) != 0) {
        return 0;
    }

    int match = (CRYPTO_memcmp(computed, record->auth_hash, USERS_HASH_LEN) == 0);
    OPENSSL_cleanse(computed, sizeof(computed));
    return match;
}

static int login_as_role(const char *username, const char *password,
                          user_role_t required_role,
                          char *out_username, size_t out_size,
                          unsigned char *out_master_key, size_t out_master_key_len,
                          const char *log_event) {
    if (username == NULL || password == NULL || out_username == NULL || out_size == 0
        || out_master_key == NULL || out_master_key_len != AUTH_MASTER_KEY_LEN) {
        return -1;
    }

    user_record_t record;
    if (users_load(username, &record) != 0 || record.role != required_role) {
        logging_event(log_event, username, "auth", "failure");
        return -1;
    }

    if (!verify_password(password, &record)) {
        logging_event(log_event, username, "auth", "failure");
        return -1;
    }

    if (crypto_pbkdf2_sha256(password, record.enc_salt, USERS_SALT_LEN,
                              record.iterations, out_master_key, out_master_key_len) != 0) {
        logging_event(log_event, username, "auth", "failure");
        return -1;
    }

    strncpy(out_username, record.username, out_size - 1);
    out_username[out_size - 1] = '\0';

    logging_event(log_event, username, "auth", "success");
    return 0;
}

int auth_login(const char *username, const char *password,
               char *out_username, size_t out_size,
               unsigned char *out_master_key, size_t out_master_key_len) {
    return login_as_role(username, password, USER_ROLE_STANDARD,
                          out_username, out_size,
                          out_master_key, out_master_key_len, "LOGIN");
}

int auth_admin_login(const char *username, const char *password,
                      char *out_username, size_t out_size,
                      unsigned char *out_master_key, size_t out_master_key_len) {
    return login_as_role(username, password, USER_ROLE_ADMIN,
                          out_username, out_size,
                          out_master_key, out_master_key_len, "ADMIN_LOGIN");
}

int auth_create_user(const char *username, const char *password) {
    if (username == NULL || password == NULL || password[0] == '\0') {
        logging_event("CREATE_USER", username, "auth", "failure");
        return -1;
    }
    if (users_exists(username)) {
        logging_event("CREATE_USER", username, "auth", "failure");
        return -1;
    }

    user_record_t record;
    memset(&record, 0, sizeof(record));
    strncpy(record.username, username, sizeof(record.username) - 1);
    record.role = USER_ROLE_STANDARD;
    record.iterations = AUTH_PBKDF2_ITERATIONS;

    if (crypto_random_bytes(record.auth_salt, USERS_SALT_LEN) != 0) {
        logging_event("CREATE_USER", username, "auth", "failure");
        return -1;
    }
    if (crypto_random_bytes(record.enc_salt, USERS_SALT_LEN) != 0) {
        logging_event("CREATE_USER", username, "auth", "failure");
        return -1;
    }

    if (crypto_pbkdf2_sha256(password, record.auth_salt, USERS_SALT_LEN,
                              record.iterations, record.auth_hash, USERS_HASH_LEN) != 0) {
        logging_event("CREATE_USER", username, "auth", "failure");
        return -1;
    }

    if (users_create(&record) != 0) {
        logging_event("CREATE_USER", username, "auth", "failure");
        return -1;
    }

    logging_event("CREATE_USER", username, "auth", "success");
    return 0;
}
