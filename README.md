# Project Overview 
A command-line tool for securely encrypting, storing, retrieving and deleting files. Course project — Project 1: Secure File Encryption and Management System.

# Scope
- File encryption and decryption (AES-256-GCM, OpenSSL)
- Password-based authentication on startup (PBKDF2-HMAC-SHA256, salted hash)
- The file-encryption key is derived from the same password, but with a separate salt (envelope-style design)
- Per-user access control (a file is only visible/accessible to the user who created it)
- Secure deletion (overwrite before unlink)
- Structured logging (JSON lines) without sensitive data
- Input validation and sanitization (path traversal, log injection)
- See docs/checkpoint1-design.md for the full architecture and threat model.

# Usage
The tool is interactive and menu-driven, not an argument-based CLI — every operation is a menu selection.

Main Menu:
1. Login
2. Create User
3. Admin Login
0. Exit
Authenticated User Menu (after logging in):
1. Encrypt File
2. Decrypt File
3. Delete File
4. List Files
0. Logout

# Admin module
One admin approach. Does not support business logic but can we use it in school project?
Creating an admin account is done via a separate command-line flag, not through the menu:
./bin/secfile --create-admin
If admin account exist then command is invalid.

## Build & run

```
make
./bin/secfile
```

To clean (e.g. after changing headers, or if something got out of sync):

```
make clean
make
```

## Repository layout

```
secure-file-tool/
├── Makefile
├── README.md
├── docs/
│   └── DESIGN.md        architecture and threat model
├── include/
│   ├── auth.h
│   ├── crypto.h
│   ├── fileops.h
│   ├── logging.h
│   ├── menu.h
│   ├── metadata.h
│   └── users.h
└── src/
    ├── main.c           startup, first-run admin, --create-admin
    ├── menu.c           menus and prompts (English)
    ├── auth.c           login and user/admin creation
    ├── users.c          user records on disk
    ├── crypto.c         AES-256-GCM and PBKDF2
    ├── fileops.c        encrypt, decrypt, delete, list
    ├── metadata.c       file ownership records
    └── logging.c        JSON audit log
```

`make` creates `bin/` (the `secfile` binary) and `obj/` (object files).

The application's data directories are created automatically on first run with `0700` permissions (owner-only access):

```
storage/    encrypted .sfm files
users/      password verifiers
metadata/   file-ownership records
logs/       audit.log
```

## Project status

- **Closed:** Checkpoint 1 — threat model, architecture, repo init
- **In process:** Checkpoint 2 — core functionality: interactive CLI menu, PBKDF2 authentication, AES-256-GCM encryption/decryption, per-user metadata, admin bootstrap. Tested end-to-end (create user → login → encrypt → decrypt → content matches original, tampered-file detection, wrong-password rejection, delete).
- **Waiting:** Checkpoint 3 — full input validation (`validation.c`), automated tests (`tests/test_*.c`), final report