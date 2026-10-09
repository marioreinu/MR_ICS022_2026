DRAFT

# A working command-line interface accepting the basic commands and file path
arguments. 

The program is menu-driven. You run ./bin/secfile and pick Login, Create User, Encrypt, Decrypt, Delete or List, and the program then asks for each file path at a prompt. The only command-line argument is --create-admin.

* Asked Ali if basic commands and file path arguments are needed in my case. Next decision after his answer.

# Basic functional file encryption and decryption using the chosen library. 

I used the OpenSSL library to encrypt and decrypt files with AES-256-GCM. I picked GCM because it doesn’t just scramble the file, it also detects if someone has changed it.

When a user encrypts a file, the program does this:
1. It turns the user’s password into a 256-bit key with PBKDF2. The key is never stored.
2. It reads the file and generates a random 12-byte IV. The IV makes sure encrypting the same file twice gives different results.
3. It encrypts the data and gets a 16-byte tag, which works like a tamper seal.
4. It saves the IV, the tag and the encrypted data into one file in the storage/ folder.
5. It overwrites the original file with zeros and deletes it, so no readable copy stays behind.

When the user decrypts, the program checks the tag first. If the password is wrong or the file was changed, decryption fails and no data comes out.

I tested it by encrypting a file and decrypting it again, and the result matched the original. I also tried a wrong password and a modified file, and both were rejected.

# Basic authentication implemented. 

I built password-based login with two roles, standard user and admin.

When a user is created, the program never stores the password. It generates a random salt and runs the password through PBKDF2-HMAC-SHA256 (210,000 iterations). Only the salt and the resulting hash are saved, in one file per user in users/, readable by the owner only.

When someone logs in, the program hashes the typed password with the stored salt and compares the result to the saved hash. I used CRYPTO_memcmp for the comparison because it takes the same time whatever the input, so timing can’t leak information. If anything fails, whether the user doesn’t exist, the password is wrong or the role is wrong, the program gives the same error. That way nobody can use the messages to find out which usernames exist.

A successful login also produces the user’s encryption key, using the same password but a different salt. That is why a stolen login hash can’t be turned into the file key.

Admin accounts work the same way but with the admin role. Only one admin is allowed, and it’s created on first run or with --create-admin, never from the menu. Every login attempt, success or failure, goes into the audit log without the password.

# First-level input validation on file paths and command arguments. 

What I did:

- Length limits: All input is read with fgets into fixed-size buffers, and an empty path is rejected. Anything longer than the buffer is cut off, so it can’t overflow memory.
- Usernames: A username may only contain letters, digits, _ and -. It can’t start with a dot, and it can’t contain / or ... This is checked before the name is ever used in a file path, so nobody can make the program open a file outside users/.
- Symlinks: Input files are opened with O_NOFOLLOW, so a symbolic link can’t redirect the program to another file.
- File size: Files over 64 MB are refused.
- Output path: Decryption creates the output file with exclusive mode ("wxb"), so it never overwrites an existing file.
- Stored files: The program doesn’t use the original filename on disk. Files are saved under a random ID, so a name like ../../x can’t affect where they go.
- No command arguments: The program is menu-driven, and --create-admin is the only argument it accepts. So there is nothing to validate there.

What is still missing:

- No central path check: There is no single function that rejects .., control characters or other bad characters in a file path. The checks above are spread across modules.

# Build and run instructions that work on a clean machine, and at least one commit per working session in the history.

In progress