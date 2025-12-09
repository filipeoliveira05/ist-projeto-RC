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


/**
 * Valida se uma string de data e hora está no formato "dd-mm-yyyy hh:mm".
 * Verifica o comprimento, os separadores e se os componentes são dígitos.
 * Não faz validação de datas/horas válidas (ex: 30 de fevereiro).
 */
bool is_valid_datetime_format(const char *datetime_str) {
    // Formato esperado: dd-mm-yyyy hh:mm (16 caracteres)
    if (strlen(datetime_str) != 16) {
        return false;
    }

    // Verificar separadores e dígitos
    // dd (0-1)
    if (!isdigit(datetime_str[0]) || !isdigit(datetime_str[1])) return false;
    // - (2)
    if (datetime_str[2] != '-') return false;
    // mm (3-4)
    if (!isdigit(datetime_str[3]) || !isdigit(datetime_str[4])) return false;
    // - (5)
    if (datetime_str[5] != '-') return false;
    // yyyy (6-9)
    if (!isdigit(datetime_str[6]) || !isdigit(datetime_str[7]) || !isdigit(datetime_str[8]) || !isdigit(datetime_str[9])) return false;
    // ' ' (10)
    if (datetime_str[10] != ' ') return false;
    // hh (11-12)
    if (!isdigit(datetime_str[11]) || !isdigit(datetime_str[12])) return false;
    // : (13)
    if (datetime_str[13] != ':') return false;
    // mm (14-15)
    if (!isdigit(datetime_str[14]) || !isdigit(datetime_str[15])) return false;

    return true;
}
