#ifndef METADATA_H
#define METADATA_H

#include <stddef.h>
#include <time.h>

#include "auth.h"
#include "fileops.h"

#define METADATA_FILE_ID_LEN 32 

typedef struct {
    char owner[AUTH_USERNAME_MAX];
    char stored_name[FILEOPS_NAME_MAX];
    char file_id[METADATA_FILE_ID_LEN + 1];
    time_t created_at;
} metadata_record_t;

int metadata_generate_file_id(char *out, size_t out_size);

int metadata_create(const metadata_record_t *record);

int metadata_load(const char *owner, const char *stored_name, metadata_record_t *out_record);

int metadata_delete(const char *owner, const char *stored_name);

typedef void (*metadata_list_callback)(const metadata_record_t *record, void *user_data);

int metadata_list(const char *owner, metadata_list_callback callback, void *user_data);

#endif
