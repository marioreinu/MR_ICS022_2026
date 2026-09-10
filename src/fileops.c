#include "fileops.h"
#include <stdio.h>

int secure_delete(const char *filename)
{
    printf("Deleting: %s\n", filename);
    return 0;
}