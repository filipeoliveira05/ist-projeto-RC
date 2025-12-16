#include "data_manager.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <dirent.h>

void handle_error(const char *msg) {
    perror(msg);
    exit(1);
}

/**
 * Verifica se um utilizador existe, procurando pela sua diretoria
 */
bool user_exists(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s", uid);
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/**
 * Verifica se o ficheiro de password de um utilizador existe
 */
bool user_password_file_exists(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_pass.txt", uid, uid);
    struct stat st;
    return stat(path, &st) == 0;
}

/**
 * Verifica se a password fornecida corresponde à guardada no ficheiro do utilizador
 */
bool check_user_password(const char *uid, const char *password) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_pass.txt", uid, uid);
    FILE *f = fopen(path, "r");
    if (f == NULL) return false;

    char stored_password[10]; // 8 chars + \n + \0
    bool result = false;
    if (fgets(stored_password, sizeof(stored_password), f) != NULL) {
        stored_password[strcspn(stored_password, "\n")] = 0;
        if (strcmp(stored_password, password) == 0) {
            result = true;
        }
    }
    fclose(f);
    return result;
}

/**
 * Verifica se um utilizador está logado, procurando pelo ficheiro _login.txt
 */
bool is_user_logged_in(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_login.txt", uid, uid);
    struct stat st;
    return stat(path, &st) == 0;
}

/**
 * Cria a estrutura de ficheiros para um novo utilizador
 */
void create_user_files(const char *uid, const char *password) {
    char path[256];

    // diretoria USERS/<uid>
    snprintf(path, sizeof(path), "USERS/%s", uid);
    mkdir(path, 0700);

    // subdiretorias CREATED e RESERVED
    snprintf(path, sizeof(path), "USERS/%s/CREATED", uid);
    mkdir(path, 0700);
    snprintf(path, sizeof(path), "USERS/%s/RESERVED", uid);
    mkdir(path, 0700);

    // ficheiro USERS/<uid>/<uid>_pass.txt
    snprintf(path, sizeof(path), "USERS/%s/%s_pass.txt", uid, uid);
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fprintf(f, "%s\n", password);
        fclose(f);
    }
}

/**
 * Cria o ficheiro de sessão para um utilizador
 */
void create_login_file(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_login.txt", uid, uid);
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fclose(f);
    }
}

/**
 * Remove o ficheiro de sessão de um utilizador
 */
void remove_login_file(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_login.txt", uid, uid);
    unlink(path);
}

/**
 * Atualiza a password de um utilizador no seu ficheiro _pass.txt
 */
bool update_user_password(const char *uid, const char *new_password) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_pass.txt", uid, uid);
    FILE *f = fopen(path, "w"); // Abre em modo de escrita, sobrescrevendo o conteúdo
    if (f == NULL) return false;

    fprintf(f, "%s\n", new_password);
    fclose(f);
    return true;
}

/**
 * Remove os ficheiros de um utilizador
 */
void remove_user_files(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_pass.txt", uid, uid);
    unlink(path);
    remove_login_file(uid);
}

/**
 * Obtém a data e hora atuais e formata-as para serem usadas em nomes de ficheiros
 * date_str: YYYYMMDD
 * time_str: HHMMSS
 */
void get_datetime_for_filename(char *date_str, char *time_str, size_t size) {
    time_t now;
    struct tm *ts;

    time(&now);
    ts = localtime(&now);

    // Formato YYYY-MM-DD
    strftime(date_str, size, "%Y%m%d", ts);
    // Formato HHMMSS
    strftime(time_str, size, "%H%M%S", ts);
}

/**
 * Cria o ficheiro END_<eid>.txt para marcar um evento como fechado
 * O ficheiro contém a data e hora de encerramento
 */
void create_end_file(const char *eid_str) {
    char path[256];
    snprintf(path, sizeof(path), "EVENTS/%s/END_%s.txt", eid_str, eid_str);
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        time_t now;
        struct tm *ts;
        char datetime_str[20]; // dd-mm-yyyy HH:MM:SS

        time(&now);
        ts = localtime(&now);
        strftime(datetime_str, sizeof(datetime_str), "%d-%m-%Y %H:%M:%S", ts);
        fprintf(f, "%s\n", datetime_str);
        fclose(f);
    }
}

/**
 * Calcula o estado atual de um evento com base nos ficheiros e na data
 */
EventState get_event_state(const char *eid_str) {
    char path[256];

    // verificar se o evento está fechado (END_.txt existe)
    snprintf(path, sizeof(path), "EVENTS/%s/END_%s.txt", eid_str, eid_str);
    struct stat st;
    if (stat(path, &st) == 0) {
        return CLOSED;
    }

    // ler os detalhes do evento para verificar data e lotação
    char start_path[256];
    snprintf(start_path, sizeof(start_path), "EVENTS/%s/START_%s.txt", eid_str, eid_str);
    FILE *start_file = fopen(start_path, "r");
    if (!start_file) {
        return -1;
    }

    char date_str[11], time_str[6];
    int total_seats;
    fscanf(start_file, "%*s %*s %*s %d %10s %5s", &total_seats, date_str, time_str);
    fclose(start_file);

    // verificar se o evento já passou
    struct tm event_tm = {0};
    sscanf(date_str, "%d-%d-%d", &event_tm.tm_mday, &event_tm.tm_mon, &event_tm.tm_year);
    sscanf(time_str, "%d:%d", &event_tm.tm_hour, &event_tm.tm_min);
    event_tm.tm_mon -= 1;
    event_tm.tm_year -= 1900;
    event_tm.tm_isdst = -1;

    time_t event_time = mktime(&event_tm);
    time_t now = time(NULL);

    if (difftime(now, event_time) > 0) {
        create_end_file(eid_str);
        return PAST;
    }

    // verificar se o evento está esgotado
    char res_path[256];
    snprintf(res_path, sizeof(res_path), "EVENTS/%s/RES_%s.txt", eid_str, eid_str);
    FILE *res_file = fopen(res_path, "r");
    if (!res_file) {
        return -1;
    }
    int reserved_seats = 0;
    fscanf(res_file, "%d", &reserved_seats);
    fclose(res_file);

    if (reserved_seats >= total_seats) {
        return SOLD_OUT;
    }

    // se nada acima se aplicar, o evento está ativo
    return ACTIVE;
}
