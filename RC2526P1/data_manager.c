#include "data_manager.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

void handle_error(const char *msg) {
    perror(msg);
    exit(1);
}

/**
 * Verifica se um utilizador existe, procurando pela sua diretoria.
 */
bool user_exists(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s", uid);
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

/**
 * Verifica se a password fornecida corresponde à guardada no ficheiro do utilizador.
 */
bool check_user_password(const char *uid, const char *password) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_pass.txt", uid, uid);
    FILE *f = fopen(path, "r");
    if (f == NULL) return false;

    char stored_password[10]; // 8 chars + \n + \0
    bool result = false;
    if (fgets(stored_password, sizeof(stored_password), f) != NULL) {
        // Remove o \n do final, se existir
        stored_password[strcspn(stored_password, "\n")] = 0;
        if (strcmp(stored_password, password) == 0) {
            result = true;
        }
    }
    fclose(f);
    return result;
}

/**
 * Verifica se um utilizador está logado, procurando pelo ficheiro _login.txt.
 */
bool is_user_logged_in(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_login.txt", uid, uid);
    struct stat st;
    return stat(path, &st) == 0;
}

/**
 * Cria a estrutura de ficheiros para um novo utilizador.
 */
void create_user_files(const char *uid, const char *password) {
    char path[256];

    // Criar diretoria USERS/<uid>
    snprintf(path, sizeof(path), "USERS/%s", uid);
    mkdir(path, 0777);

    // Criar subdiretorias CREATED e RESERVED
    snprintf(path, sizeof(path), "USERS/%s/CREATED", uid);
    mkdir(path, 0777);
    snprintf(path, sizeof(path), "USERS/%s/RESERVED", uid);
    mkdir(path, 0777);

    // Criar ficheiro USERS/<uid>/<uid>_pass.txt
    snprintf(path, sizeof(path), "USERS/%s/%s_pass.txt", uid, uid);
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        fprintf(f, "%s\n", password);
        fclose(f);
    }
}

/**
 * Cria o ficheiro de sessão para um utilizador.
 */
void create_login_file(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_login.txt", uid, uid);
    FILE *f = fopen(path, "w");
    if (f != NULL) {
        // O conteúdo não importa, apenas a existência do ficheiro.
        fclose(f);
    }
}

/**
 * Remove o ficheiro de sessão de um utilizador (logout).
 */
void remove_login_file(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_login.txt", uid, uid);
    unlink(path);
}

/**
 * Remove os ficheiros de um utilizador (unregister).
 * De acordo com o guia, apenas _pass.txt e _login.txt são removidos.
 */
void remove_user_files(const char *uid) {
    char path[256];
    snprintf(path, sizeof(path), "USERS/%s/%s_pass.txt", uid, uid);
    unlink(path);
    remove_login_file(uid); // Reutiliza a função de logout
}
