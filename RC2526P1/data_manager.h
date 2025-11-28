#ifndef DATA_MANAGER_H
#define DATA_MANAGER_H

#include "structures.h"
#include <stddef.h> // Para o tipo size_t

// Função de utilidade para tratamento de erros
void handle_error(const char *msg);

// Funções de gestão de utilizadores baseadas em ficheiros
bool user_exists(const char *uid);
bool user_password_file_exists(const char *uid);
bool check_user_password(const char *uid, const char *password);
bool is_user_logged_in(const char *uid);
void create_user_files(const char *uid, const char *password);
void create_login_file(const char *uid);
void remove_login_file(const char *uid);
void remove_user_files(const char *uid);

// Funções de utilidade para datas
void get_datetime_for_filename(char *date_str, char *time_str, size_t size);


#endif
