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
    char uid[7];        // UID de 6 dígitos + '\0'.
    char password[9];   // Password de 8 caracteres + '\0'.
    bool is_logged_in;  // Flag para saber se o user tem sessão ativa.
    struct User* next;  // Pointer para o próximo user numa linked list.
} User;


/*
 * Estrutura para armazenar uma reserva feita por um user num evento.
 */
typedef struct Reservation {
    char uid[7];                  // UID do user que fez a reserva.
    int reserved_seats;           // Número de lugares reservados.
    struct Reservation* next;     // Ponteiro para a próxima reserva no mesmo evento.
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
    EventState state;             // Estado atual do evento (ACTIVE, PAST, SOLD_OUT, CLOSED).
    Reservation* reservations;    // Linked list de reservas para este evento.
    struct Event* next;           // Pointer para o próximo evento numa linked list.
} Event;


/*
 * Estrutura principal do servidor para gerir todo o estado.
 * Agrupa as listas de users e eventos num só local.
 */
typedef struct ServerState {
    User* users;    // Head da linked list de users.
    Event* events;  // Head da linked liss de eventos.
    int next_eid;   // Contador para atribuir o próximo EID disponível.
} ServerState;


#endif