#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "menu.h"
#include "auth.h"
#include "users.h"
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

/* ---- --create-admin bootstrap ---------------------------------------- */

static void flush_stdin_line(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
        /* discard */
    }
}

static int read_line(char *buf, size_t buf_size) {
    if (buf_size == 0) {
        return 0;
    }
    if (fgets(buf, (int)buf_size, stdin) == NULL) {
        buf[0] = '\0';
        return 0;
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    } else {
        flush_stdin_line();
    }
    return 1;
}

static int read_password_line(char *buf, size_t buf_size) {
    struct termios oldt;
    int have_tty = (tcgetattr(STDIN_FILENO, &oldt) == 0);

    if (have_tty) {
        struct termios newt = oldt;
        newt.c_lflag &= ~((tcflag_t)ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }

    int ok = read_line(buf, buf_size);

    if (have_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        printf("\n");
    }
    return ok;
}

static int prompt_create_admin_credentials(void) {
    char username[AUTH_USERNAME_MAX];
    char password[AUTH_PASSWORD_MAX];
    char password_confirm[AUTH_PASSWORD_MAX];

    printf("Admin username: ");
    fflush(stdout);
    if (!read_line(username, sizeof(username)) || username[0] == '\0') {
        fprintf(stderr, "Username is required.\n");
        return EXIT_FAILURE;
    }

    printf("Admin password: ");
    fflush(stdout);
    if (!read_password_line(password, sizeof(password))) {
        fprintf(stderr, "Failed to read password.\n");
        return EXIT_FAILURE;
    }
    printf("Confirm password: ");
    fflush(stdout);
    if (!read_password_line(password_confirm, sizeof(password_confirm))) {
        memset(password, 0, sizeof(password));
        fprintf(stderr, "Failed to read password.\n");
        return EXIT_FAILURE;
    }

    if (strcmp(password, password_confirm) != 0) {
        memset(password, 0, sizeof(password));
        memset(password_confirm, 0, sizeof(password_confirm));
        fprintf(stderr, "Passwords do not match.\n");
        return EXIT_FAILURE;
    }

    int result = auth_create_admin(username, password);

    memset(password, 0, sizeof(password));
    memset(password_confirm, 0, sizeof(password_confirm));

    if (result == 0) {
        printf("Admin account '%s' created.\n", username);
        return EXIT_SUCCESS;
    }

    fprintf(stderr, "Failed to create admin account (username may already exist).\n");
    return EXIT_FAILURE;
}

static int run_create_admin(void) {
    /* Check first, before asking for a username/password — no point
     * making someone type credentials just to be refused afterwards. */
    int admin_exists = users_admin_exists();
    if (admin_exists != 0) {
        fprintf(stderr, "An admin account already exists — only one admin account is allowed.\n");
        return EXIT_FAILURE;
    }

    printf("-- Create admin account --\n");
    return prompt_create_admin_credentials();
}

static void bootstrap_admin_on_first_run(void) {
    if (users_admin_exists() != 0) {
        return;
    }

    printf("No admin account found — creating one before continuing.\n");
    printf("-- Create admin account --\n");
    if (prompt_create_admin_credentials() != EXIT_SUCCESS) {
        fprintf(stderr,
                "Admin account was not created. The application will continue, but\n"
                "admin features will not be available until an admin account is\n"
                "created (e.g. ./secfile --create-admin).\n");
    }
}

int main(int argc, char *argv[]) {
    if (ensure_directory_layout() != 0) {
        return EXIT_FAILURE;
    }

    if (logging_init("logs/audit.log") != 0) {
        fprintf(stderr, "Startup failed: could not initialize logging.\n");
        return EXIT_FAILURE;
    }

    if (argc == 2 && strcmp(argv[1], "--create-admin") == 0) {
        int rc = run_create_admin();
        logging_close();
        return rc;
    }

    logging_event("APP_START", NULL, "main", "success");

    bootstrap_admin_on_first_run();

    int exit_code = menu_run();

    logging_event("APP_EXIT", NULL, "main", exit_code == 0 ? "success" : "failure");
    logging_close();

    return exit_code == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}