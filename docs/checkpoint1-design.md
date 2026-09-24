# Project Overview
The application allows authenticated users to encrypt, decrypt and securely delete files while applying secure coding practices.

# System Architecture
+----------------------+
|      User CLI        |
|      (Menus)         |
+----------+-----------+
           |
           v
+----------------------+
| Menu Module          |
| menu.c / menu.h      |
+----------+-----------+
           |
           v
+----------------------+
| Authentication       |
| auth.c / users.c     |
+----------+-----------+
           |
           v
+----------------------+
| Command Processor    |
| User Session         |
+----------+-----------+
           |
  +--------+--------+--------+--------+
  |        |        |        |        |
  v        v        v        v        v
Encrypt  Decrypt  Delete   List   Change
Module   Module   Module   Files Password
  |         |        |        |        |
  +---------+--------+--------+--------+
                       |
                       v
+----------------------+
| Input Validation     |
| validation.c         |
+----------+-----------+
           |
           v
+----------------------+
| File Operations      |
| fileops.c            |
+----------+-----------+
           |
  +--------+--------+
  |                 |
  v                 v
+----------------+  +----------------+
| Crypto Module  |  | Metadata       |
| AES-256-GCM    |  | Ownership DB   |
| PBKDF2         |  | files.db       |
+-------+--------+  +-------+--------+
        |                   |
- - - - | - - - - - - - - - | - - - - - -  <- Trust boundary: everything above
        |                   |               this line runs inside one trusted
        +---------+---------+               local process (the running CLI).
                  |                          Everything below is persistent
                  v                          state on disk that an attacker
+----------------------+                     with filesystem access could
| Secure Storage       |                     read/tamper with directly.
| bin/storage/*.sfm        |
+----------+-----------+
           |
           v
+----------------------+
| Audit Logger         |
| bin/logs/audit.log       |
+----------------------+

# Trust boundary
 The Menu, Authentication, Command Processor, all per-operation modules, Input Validation, File Operations and the Crypto module all execute inside a single trusted local process — the running `secfile` CLI, under the invoking OS user's privileges. `bin/storage/*.sfm`, `bin/metadata/*`, `bin/users/*` and `bin/logs/audit.log` sit outside that boundary: they are plain files on disk. Anything written there must be safe to expose to an attacker who can read or modify the filesystem directly but cannot execute code inside the running process — i.e. file contents must be encrypted (not merely access-controlled), password verifiers must be salted hashes (not recoverable), and log entries must never contain secrets, since none of these have any protection beyond OS file permissions once they leave the process boundary.

# Threat Model
- Buffer Overflow: safe functions and bounds checks.
- Path Traversal: input validation.
- Weak Password Storage: PBKDF2 + salt.
- Unauthorized Access: ownership checks.
- File Theft: AES-256-GCM.
- Information Disclosure: generic errors and safe logging.
- Key/Password Handling in Memory: the derived encryption key (from PBKDF2) and the plaintext password typed at login exist in process memory for as long as an operation needs them. If left in heap or stack memory after use, they are exposed to memory-dump attacks, swap-file leakage, or a crash report capturing process memory. Mitigation: zero out key and password buffers immediately after use (`OPENSSL_cleanse()` or `explicit_bzero()`, not a plain `memset` that the compiler may optimize away); never write the raw key or password to disk, swap, or logs at any point; keep the key's lifetime scoped as tightly as possible around the single encrypt/decrypt call that needs it.

# Implementation Language and Libraries
- C (C17)
- OpenSSL (libcrypto)
- Standard C library**

# Justification 
OpenSSL is a mature, widely audited cryptographic library that ships ready-made AES-256-GCM (authenticated encryption, so tampering is detected, not just confidentiality protected) and PBKDF2 key-derivation primitives, which avoids implementing custom cryptography — a common source of critical vulnerabilities. C is required by the assignment's focus on low-level secure coding (manual memory management, buffer-overflow prevention), and pairing it with OpenSSL keeps the cryptographic core itself out of hand-rolled code while the rest of the application (input validation, file handling, memory hygiene) is where the course's secure-coding practices are actually exercised.

# The application uses an interactive command-line menu.
Main Menu:
1. Login
2. Create User
3. Admin Login
0. Exit

Authenticated User Menu:
1. Encrypt File
2. Decrypt File
3. Delete File
4. List Files
0. Logout

# Repository Structure
MR_ICS022_2026/
├── bin/
│   ├── metadata/             # file ownership and metadata records
│   ├── logs/
│   ├── secfile               # executable to start CLI application 
│   ├── storage/              # encrypted .sfm objects only
│   └── users/                # password verifiers and user records
├── docs/
│   ├── checkpoint1-design.md
│   ├── checkpoint2-core_requirements.md
│   └── checkpoint3-near_final.md
├── include/
│   ├── menu.h            # interactive CLI menus and user selections
│   ├── auth.h            # registration, login and password verification
│   ├── users.h           # user records, roles and password changes
│   ├── crypto.h          # PBKDF2 KDF and AES-256-GCM operations
│   ├── fileops.h         # encrypt, decrypt, delete and list operations
│   ├── metadata.h        # file ownership and encrypted file records
│   ├── logging.h         # structured audit events
│   └── validation.h      # input, filename, username and path validation         
├── obj/
├── src/
│   ├── main.c            # application startup and main menu loop
│   ├── menu.c
│   ├── auth.c
│   ├── users.c
│   ├── crypto.c
│   ├── fileops.c
│   ├── logging.c
│   ├── metadata.c
│   └── validation.c
├── tests/
│   ├── test_auth.c
│   ├── test_crypto.c
│   ├── test_fileops.c
│   └── test_validation.c
└── .gitkeep
├── Makefile
├── README.md
└── .gitignore