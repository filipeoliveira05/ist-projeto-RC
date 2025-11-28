#include "data_manager.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void handle_error(const char *msg) {
    perror(msg);
    exit(1);
}

// --- Funções Auxiliares para Gestão de Utilizadores ---

/*
 * Remove um user da linked list de users do servidor.
 */
void remove_user(ServerState *state, const char *uid) {
    User *current = state->users, *prev = NULL;

    // Se o user a remover for o primeiro da lista
    if (current != NULL && strcmp(current->uid, uid) == 0) {
        state->users = current->next;
        free(current);
        return;
    }

    // Procura o user na lista
    while (current != NULL && strcmp(current->uid, uid) != 0) {
        prev = current;
        current = current->next;
    }

    // Se o user não foi encontrado
    if (current == NULL) return;

    // Remove o user da linked list
    prev->next = current->next;

    free(current); // Liberta a memória alocada ao user
}

/*
 * Procura um user na linked list pelo seu UID.
 * Retorna um pointer para o user se encontrado, ou NULL caso contrário.
 */
User* find_user_by_uid(ServerState *state, const char *uid) {
    User* current = state->users;
    while (current != NULL) {
        if (strcmp(current->uid, uid) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/*
 * Adiciona um novo user à linked list de users do servidor.
 * Retorna um pointer para o novo user criado.
 */
User* add_user(ServerState *state, const char *uid, const char *password) {
    User* new_user = (User*)malloc(sizeof(User));
    if (new_user == NULL) {
        handle_error("Erro ao alocar memória para novo user");
    }

    strncpy(new_user->uid, uid, sizeof(new_user->uid) - 1);
    new_user->uid[sizeof(new_user->uid) - 1] = '\0';

    strncpy(new_user->password, password, sizeof(new_user->password) - 1);
    new_user->password[sizeof(new_user->password) - 1] = '\0';

    new_user->is_logged_in = true; // Novo user é automaticamente logado
    new_user->next = state->users; // Adiciona no início da linked list
    state->users = new_user;

    return new_user;
}

/*
 * Adiciona um novo evento à lista ligada de eventos do servidor.
 */
Event* add_event(ServerState *state, const char *owner_uid, const char *name, const char *date, int total_seats, const char *filename) {
    Event* new_event = (Event*)malloc(sizeof(Event));
    if (new_event == NULL) {
        handle_error("Erro ao alocar memória para novo evento");
    }

    new_event->eid = state->next_eid++;
    strncpy(new_event->owner_uid, owner_uid, sizeof(new_event->owner_uid) - 1);
    strncpy(new_event->name, name, sizeof(new_event->name) - 1);
    new_event->name[sizeof(new_event->name) - 1] = '\0'; // Garantir terminação nula
    strncpy(new_event->date, date, sizeof(new_event->date) - 1);
    new_event->date[sizeof(new_event->date) - 1] = '\0'; // Garantir terminação nula
    new_event->total_seats = total_seats;
    strncpy(new_event->filename, filename, sizeof(new_event->filename) - 1);

    new_event->reserved_seats = 0;
    new_event->state = ACTIVE;
    new_event->reservations = NULL;
    new_event->next = state->events;
    state->events = new_event;
    return new_event;
}
