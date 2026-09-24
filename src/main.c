#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include "menu.h"
#include "logging.h"

static const char *REQUIRED_DIRS[] = {
    "storage",
    "users",
    "metadata",
    "logs"
};
static const size_t REQUIRED_DIR_COUNT = sizeof(REQUIRED_DIRS) / sizeof(REQUIRED_DIRS[0]);
static int ensure_directory(const char *path) {
    if (mkdir(path, 0700) == 0) {
        return 0;
    }
    if (errno == EEXIST) {
        return 0;
    }
    return -1;
}

static int ensure_directory_layout(void) {
    for (size_t i = 0; i < REQUIRED_DIR_COUNT; i++) {
        if (ensure_directory(REQUIRED_DIRS[i]) != 0) {
            fprintf(stderr, "Startup failed: could not prepare application storage.\n");
            return -1;
        }
    }
    return 0;
}

int main(void) {
    if (ensure_directory_layout() != 0) {
        return EXIT_FAILURE;
    }

    if (logging_init("logs/audit.log") != 0) {
        fprintf(stderr, "Startup failed: could not initialize logging.\n");
        return EXIT_FAILURE;
    }

    logging_event("APP_START", NULL, "main", "success");

    int exit_code = menu_run();

    logging_event("APP_EXIT", NULL, "main", exit_code == 0 ? "success" : "failure");
    logging_close();

    return exit_code == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}