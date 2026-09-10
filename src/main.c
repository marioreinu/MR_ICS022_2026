#include <stdio.h>

#include "auth.h"
#include "crypto.h"
#include "fileops.h"
#include "logging.h"

int main(void)
{
    printf("Secure File Encryption and Management System\n");

    authenticate_user();

    log_event(
        "startup",
        "test_user",
        "success"
    );

    return 0;
}