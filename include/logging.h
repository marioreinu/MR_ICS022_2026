#ifndef LOGGING_H
#define LOGGING_H

int logging_init(const char *log_path);

void logging_event(const char *event, const char *user, const char *source, const char *outcome);

void logging_close(void);

#endif
