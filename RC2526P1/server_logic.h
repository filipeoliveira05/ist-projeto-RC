#ifndef SERVER_LOGIC_H
#define SERVER_LOGIC_H

#include "structures.h"
#include <sys/socket.h>
#include <netinet/in.h>

// Processa um pedido UDP completo
void process_udp_request(int udp_fd, struct sockaddr_in *client_addr, char *buffer, ServerState *server_data, bool verbose);

// Processa um pedido TCP completo
void process_tcp_request(int client_fd, char *buffer, ssize_t buffer_size, ServerState *server_data, bool verbose, char *response_buffer, int response_size);

#endif
