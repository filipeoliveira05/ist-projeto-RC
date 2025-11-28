#ifndef DATA_MANAGER_H
#define DATA_MANAGER_H

#include "structures.h"

// Função de utilidade para tratamento de erros
void handle_error(const char *msg);

// Funções de gestão de utilizadores
User* find_user_by_uid(ServerState *state, const char *uid);
User* add_user(ServerState *state, const char *uid, const char *password);
void remove_user(ServerState *state, const char *uid);

// Funções de gestão de eventos
Event* add_event(ServerState *state, const char *owner_uid, const char *name, const char *date, int total_seats, const char *filename);

#endif
