#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "menu.h"
#include "auth.h"
#include "fileops.h"
#include "crypto.h"

#define MENU_CHOICE_BUF_SIZE 8

static void flush_stdin_line(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {
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

static int read_menu_choice(int *out) {
    char buf[MENU_CHOICE_BUF_SIZE];
    if (!read_line(buf, sizeof(buf)) || buf[0] == '\0') {
        return 0;
    }

    char *endptr = NULL;
    long val = strtol(buf, &endptr, 10);
    if (endptr == buf || *endptr != '\0' || val < 0 || val > 9) {
        printf("Please enter a number in the range 0-9.\n");
        return 0;
    }

    *out = (int)val;
    return 1;
}

static int prompt_line(const char *label, char *buf, size_t buf_size) {
    printf("%s: ", label);
    fflush(stdout);
    return read_line(buf, buf_size);
}

static int prompt_password(const char *label, char *buf, size_t buf_size) {
    printf("%s: ", label);
    fflush(stdout);
    return read_password_line(buf, buf_size);
}


static void print_user_menu(const char *username) {
    printf("\n-- USER: %s --\n", username);
    printf("1. Encrypt File\n");
    printf("2. Decrypt File\n");
    printf("3. Delete File\n");
    printf("4. List Files\n");
    printf("0. Logout\n");
}

static void handle_encrypt(const char *username, const unsigned char *key) {
    char path[FILEOPS_NAME_MAX];
    if (!prompt_line("File path to encrypt", path, sizeof(path)) || path[0] == '\0') {
        printf("Cancelled.\n");
        return;
    }
    if (fileops_encrypt(username, key, AUTH_MASTER_KEY_LEN, path) == 0) {
        printf("File encrypted and saved.\n");
    } else {
        printf("Encryption failed.\n");
    }
}

static void handle_decrypt(const char *username, const unsigned char *key) {
    char stored_name[FILEOPS_NAME_MAX];
    char output_path[FILEOPS_NAME_MAX];
    if (!prompt_line("Stored file name", stored_name, sizeof(stored_name)) || stored_name[0] == '\0') {
        printf("Cancelled.\n");
        return;
    }
    if (!prompt_line("Output file path", output_path, sizeof(output_path)) || output_path[0] == '\0') {
        printf("Cancelled.\n");
        return;
    }
    if (fileops_decrypt(username, key, AUTH_MASTER_KEY_LEN, stored_name, output_path) == 0) {
        printf("File decrypted.\n");
    } else {
        printf("Decryption failed.\n");
    }
}

static void handle_delete(const char *username) {
    char stored_name[FILEOPS_NAME_MAX];
    char confirm[8];
    if (!prompt_line("File name to delete", stored_name, sizeof(stored_name)) || stored_name[0] == '\0') {
        printf("Cancelled.\n");
        return;
    }
    if (!prompt_line("Confirm deletion (y/n)", confirm, sizeof(confirm))) {
        printf("Cancelled.\n");
        return;
    }
    if (confirm[0] != 'y' && confirm[0] != 'Y') {
        printf("Deletion cancelled.\n");
        return;
    }
    if (fileops_delete(username, stored_name) == 0) {
        printf("File deleted.\n");
    } else {
        printf("Deletion failed.\n");
    }
}

static void handle_list(const char *username) {
    if (fileops_list(username) != 0) {
        printf("Failed to load the list of files.\n");
    }
}

static void run_authenticated_session(const char *username, const unsigned char *key) {
    int logged_in = 1;
    while (logged_in) {
        print_user_menu(username);
        int choice;
        if (!read_menu_choice(&choice)) {
            continue;
        }
        switch (choice) {
            case 1: handle_encrypt(username, key); break;
            case 2: handle_decrypt(username, key); break;
            case 3: handle_delete(username); break;
            case 4: handle_list(username); break;
            case 0: logged_in = 0; break;
            default: printf("Invalid option.\n"); break;
        }
    }
}


static void print_main_menu(void) {
    printf("\n-- Main Menu --\n");
    printf("1. Login\n");
    printf("2. Create User\n");
    printf("3. Admin Login\n");
    printf("0. Exit\n");
}

static void handle_login(void) {
    char username[AUTH_USERNAME_MAX];
    char password[AUTH_PASSWORD_MAX];
    char canonical_username[AUTH_USERNAME_MAX];
    unsigned char master_key[AUTH_MASTER_KEY_LEN];

    if (!prompt_line("Username", username, sizeof(username)) || username[0] == '\0') {
        return;
    }
    if (!prompt_password("Password", password, sizeof(password))) {
        return;
    }

    int result = auth_login(username, password, canonical_username, sizeof(canonical_username),
                             master_key, sizeof(master_key));


    memset(password, 0, sizeof(password));

    if (result == 0) {
        printf("Login successful.\n");
        run_authenticated_session(canonical_username, master_key);
    } else {
        printf("Invalid username or password.\n");
    }

    crypto_zero(master_key, sizeof(master_key));
}

static void handle_create_user(void) {
    char username[AUTH_USERNAME_MAX];
    char password[AUTH_PASSWORD_MAX];
    char password_confirm[AUTH_PASSWORD_MAX];

    if (!prompt_line("New username", username, sizeof(username)) || username[0] == '\0') {
        return;
    }
    if (!prompt_password("Password", password, sizeof(password))) {
        return;
    }
    if (!prompt_password("Confirm password", password_confirm, sizeof(password_confirm))) {
        memset(password, 0, sizeof(password));
        return;
    }

    if (strcmp(password, password_confirm) != 0) {
        printf("Passwords do not match.\n");
        memset(password, 0, sizeof(password));
        memset(password_confirm, 0, sizeof(password_confirm));
        return;
    }

    int result = auth_create_user(username, password);

    memset(password, 0, sizeof(password));
    memset(password_confirm, 0, sizeof(password_confirm));

    if (result == 0) {
        printf("User created successfully.\n");
    } else {
        printf("Failed to create user.\n");
    }
}

static void handle_admin_login(void) {
    char username[AUTH_USERNAME_MAX];
    char password[AUTH_PASSWORD_MAX];
    char canonical_username[AUTH_USERNAME_MAX];
    unsigned char master_key[AUTH_MASTER_KEY_LEN];

    if (!prompt_line("Admin username", username, sizeof(username)) || username[0] == '\0') {
        return;
    }
    if (!prompt_password("Admin password", password, sizeof(password))) {
        return;
    }

    int result = auth_admin_login(username, password, canonical_username, sizeof(canonical_username),
                                   master_key, sizeof(master_key));
    memset(password, 0, sizeof(password));

    if (result == 0) {
        printf("Admin login successful.\n");

        run_authenticated_session(canonical_username, master_key);
    } else {
        printf("Invalid admin username or password.\n");
    }

    crypto_zero(master_key, sizeof(master_key));
}

int menu_run(void) {
    int running = 1;
    while (running) {
        print_main_menu();
        int choice;
        if (!read_menu_choice(&choice)) {
            continue;
        }
        switch (choice) {
            case 1: handle_login(); break;
            case 2: handle_create_user(); break;
            case 3: handle_admin_login(); break;
            case 0: running = 0; break;
            default: printf("Vigane valik.\n"); break;
        }
    }
    return 0;
}
