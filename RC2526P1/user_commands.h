#ifndef USER_COMMANDS_H
#define USER_COMMANDS_H

#include "structures.h"
#include <stdbool.h> // Para bool
#include <sys/types.h> // Para ssize_t
#include <netinet/in.h> // Para struct sockaddr_in
#include <netdb.h>      // Para struct hostent

// Função de utilidade para tratamento de erros no cliente
void user_handle_error(const char *msg);

// Funções para processar comandos do utilizador
void handle_login_command(ClientState *client_state, const char *uid, const char *password);
void handle_logout_command(ClientState *client_state);
void handle_unregister_command(ClientState *client_state);
void handle_create_command(ClientState *client_state, const char *name, const char *event_fname, const char *date, const char *time, const char *num_attendees);
void handle_list_command(ClientState *client_state);
void handle_show_command(ClientState *client_state, const char *eid);
void handle_close_command(ClientState *client_state, const char *eid);
void handle_reserve_command(ClientState *client_state, const char *eid, const char *num_seats);
void handle_myevents_command(ClientState *client_state);
void handle_myreservations_command(ClientState *client_state);
void handle_exit_command(ClientState *client_state);

// Funções auxiliares de comunicação (se necessário, podem ser internas a user_commands.c)
int create_udp_socket_and_connect(ClientState *client_state, struct sockaddr_in *server_addr_out);
int create_tcp_socket_and_connect(ClientState *client_state, struct sockaddr_in *server_addr_out);


#endif
