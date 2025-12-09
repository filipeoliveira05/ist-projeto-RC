#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h> // Para o tipo bool

bool is_valid_password(const char *password);
bool is_valid_uid(const char *uid);
bool is_valid_event_name(const char *name);
bool is_valid_event_filename(const char *filename);
bool is_valid_datetime_format(const char *datetime_str);
#endif // UTILS_H