#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "logging.h"

#define LOG_FIELD_MAX 128

static FILE *log_fp = NULL;

static void json_escape(const char *src, char *dst, size_t dst_size) {
    if (dst_size == 0) {
        return;
    }
    if (src == NULL) {
        src = "-";
    }

    size_t out = 0;
    for (size_t i = 0; src[i] != '\0' && out + 1 < dst_size; i++) {
        unsigned char c = (unsigned char)src[i];

        if (c == '"' || c == '\\') {
            if (out + 2 >= dst_size) {
                break;
            }
            dst[out++] = '\\';
            dst[out++] = (char)c;
        } else if (c == '\n' || c == '\r' || c < 0x20) {

            if (out + 1 >= dst_size) {
                break;
            }
            dst[out++] = ' ';
        } else {
            dst[out++] = (char)c;
        }
    }
    dst[out] = '\0';
}

int logging_init(const char *log_path) {
    if (log_path == NULL) {
        return -1;
    }

    FILE *fp = fopen(log_path, "a");
    if (fp == NULL) {
        return -1;
    }

    if (chmod(log_path, S_IRUSR | S_IWUSR) != 0) {
        fclose(fp);
        return -1;
    }

    log_fp = fp;
    return 0;
}

void logging_event(const char *event, const char *user, const char *source, const char *outcome) {
    if (log_fp == NULL) {
        return;
    }

    time_t now = time(NULL);
    struct tm tm_utc;
    char timestamp[32];

    if (gmtime_r(&now, &tm_utc) == NULL) {
        strncpy(timestamp, "1970-01-01T00:00:00Z", sizeof(timestamp) - 1);
        timestamp[sizeof(timestamp) - 1] = '\0';
    } else {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
    }

    char safe_event[LOG_FIELD_MAX];
    char safe_user[LOG_FIELD_MAX];
    char safe_source[LOG_FIELD_MAX];
    char safe_outcome[LOG_FIELD_MAX];

    json_escape(event, safe_event, sizeof(safe_event));
    json_escape(user, safe_user, sizeof(safe_user));
    json_escape(source, safe_source, sizeof(safe_source));
    json_escape(outcome, safe_outcome, sizeof(safe_outcome));

    fprintf(log_fp,
            "{\"timestamp\":\"%s\",\"event\":\"%s\",\"user\":\"%s\",\"source\":\"%s\",\"outcome\":\"%s\"}\n",
            timestamp, safe_event, safe_user, safe_source, safe_outcome);

    fflush(log_fp);
}

void logging_close(void) {
    if (log_fp != NULL) {
        fclose(log_fp);
        log_fp = NULL;
    }
}
