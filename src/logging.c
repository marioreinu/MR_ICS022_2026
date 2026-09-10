#include "logging.h"
#include <stdio.h>

void log_event(const char *event,
               const char *user,
               const char *status)
{
    printf(
        "[LOG] event=%s user=%s status=%s\n",
        event,
        user,
        status
    );
}