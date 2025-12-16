#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <stdbool.h>

/*
 * Enum para representar os diferentes estados de um evento.
 * - ACTIVE: Futuro e aceita reservas (1).
 * - PAST: A data já passou (0).
 * - SOLD_OUT: Futuro mas esgotado (2).
 * - CLOSED: Fechado pelo proprietário (3).
 */
typedef enum {
    PAST = 0,
    ACTIVE = 1,
    SOLD_OUT = 2,
    CLOSED = 3
} EventState;


/*
 * Estrutura para armazenar a informação de um user.
 */
typedef struct User {
    char uid[7];
    char password[9];
} User;


/*
 * Estrutura para armazenar a informação de um evento.
 */
typedef struct Event {
    int eid;
    char name[11];
    char date[17];
    int total_seats;
    int reserved_seats;
    char owner_uid[7];
    char filename[25];
    EventState state;
} Event;


/*
 * Estrutura principal do servidor para gerir todo o estado.
 * Agrupa as listas de users e eventos num só local.
 */
typedef struct ServerState {
    int next_eid;
} ServerState;

/*
 * Estrutura principal do cliente para gerir todo o estado.
 */
typedef struct ClientState {
    char current_uid[7];
    char current_password[9];
    bool is_logged_in;
    char *server_ip;
    int server_port;
    struct hostent *host_info;
} ClientState;


#endif