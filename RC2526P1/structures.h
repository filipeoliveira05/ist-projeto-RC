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
    char uid[7];       // UID de 6 dígitos + '\0'.
    char password[9];  // Password de 8 caracteres + '\0'.
} Reservation;


/*
 * Estrutura para armazenar a informação de um evento.
 */
typedef struct Event {
    int eid;                      // ID do evento (1 a 999).
    char name[11];                // Nome do evento (max 10 chars + '\0').
    char date[17];                // Data no formato "dd-mm-yyyy hh:mm" (16 chars) + '\0'.
    int total_seats;              // Número total de lugares (10 a 999).
    int reserved_seats;           // Número de lugares já reservados.
    char owner_uid[7];            // UID do user que criou o evento.
    char filename[25];            // Nome do ficheiro de descrição (max 24 chars + '\0').
    EventState state;             // Estado atual do evento (calculado dinamicamente).
} Event; // Renomeado para evitar conflito com struct Event em server_logic.c


/*
 * Estrutura principal do servidor para gerir todo o estado.
 * Agrupa as listas de users e eventos num só local.
 */
typedef struct ServerState {
    int next_eid;   // Contador para atribuir o próximo EID disponível.
} ServerState;

/*
 * Estrutura principal do cliente para gerir todo o estado.
 */
typedef struct ClientState {
    char current_uid[7];        // UID do utilizador atualmente logado.
    char current_password[9];   // Password do utilizador atualmente logado.
    bool is_logged_in;          // Flag para saber se o user tem sessão ativa.
    char *server_ip;            // IP do servidor de eventos.
    int server_port;            // Porta do servidor de eventos.
    struct hostent *host_info;  // Informação do host do servidor.
} ClientState;


#endif