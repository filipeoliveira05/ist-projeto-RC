#include "utils.h"
#include <string.h> // Para strlen
#include <ctype.h>  // Para isalnum

/**
 * Valida se uma password tem exatamente 8 caracteres e se são todos alfanuméricos.
 */
bool is_valid_password(const char *password) {
    if (strlen(password) != 8) {
        return false;
    }
    for (int i = 0; password[i] != '\0'; i++) {
        if (!isalnum((unsigned char)password[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Valida se um UID tem exatamente 6 caracteres e se são todos dígitos.
 */
bool is_valid_uid(const char *uid) {
    if (strlen(uid) != 6) {
        return false;
    }
    for (int i = 0; uid[i] != '\0'; i++) {
        if (!isdigit((unsigned char)uid[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Valida se o nome de um evento tem no máximo 10 caracteres e se são todos alfanuméricos.
 */
bool is_valid_event_name(const char *name) {
    if (strlen(name) == 0 || strlen(name) > 10) {
        return false;
    }
    for (int i = 0; name[i] != '\0'; i++) {
        if (!isalnum((unsigned char)name[i])) {
            return false;
        }
    }
    return true;
}

/**
 * Valida se o nome de um ficheiro de evento tem no máximo 24 caracteres e se contém apenas caracteres alfanuméricos, '-', '_' ou '.'.
 */
bool is_valid_event_filename(const char *filename) {
    if (strlen(filename) == 0 || strlen(filename) > 24) {
        return false;
    }
    for (int i = 0; filename[i] != '\0'; i++) {
        if (!isalnum((unsigned char)filename[i]) && filename[i] != '-' && filename[i] != '_' && filename[i] != '.') {
            return false;
        }
    }
    return true;
}