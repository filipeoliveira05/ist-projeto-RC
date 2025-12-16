#include "utils.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

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
 * Verifica o formato, os separadores e a validade lógica dos valores.
 */
bool is_valid_datetime_format(const char *datetime_str) {
    int day, month, year, hour, minute;

    if (sscanf(datetime_str, "%d-%d-%d %d:%d", &day, &month, &year, &hour, &minute) != 5) {
        return false;
    }

    if (year < 1900 || year > 9999) return false;
    if (month < 1 || month > 12) return false;
    if (hour < 0 || hour > 23) return false;
    if (minute < 0 || minute > 59) return false;

    int days_in_month;
    if (month == 2) {
        bool is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        days_in_month = is_leap ? 29 : 28;
    } else if (month == 4 || month == 6 || month == 9 || month == 11) {
        days_in_month = 30;
    } else {
        days_in_month = 31;
    }

    if (day < 1 || day > days_in_month) {
        return false;
    }

    char check_buffer[20];
    snprintf(check_buffer, sizeof(check_buffer), "%02d-%02d-%04d %02d:%02d", day, month, year, hour, minute);
    if (strcmp(datetime_str, check_buffer) != 0) {
        if (strlen(datetime_str) != 16 || datetime_str[2] != '-' || datetime_str[5] != '-' || datetime_str[10] != ' ' || datetime_str[13] != ':') {
            return false;
        }
    }

    return true;
}

/**
 * Valida se o número de lugares é uma string que representa um inteiro entre 10 e 999.
 */
bool is_valid_number_attendees(const char *num_str) {
    for (int i = 0; num_str[i] != '\0'; i++) {
        if (!isdigit((unsigned char)num_str[i])) {
            return false;
        }
    }

    int num = atoi(num_str);
    if (num < 10 || num > 999) {
        return false;
    }
    return true;
}
