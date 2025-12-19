#define _POSIX_C_SOURCE 200809L

#include "server_logic.h"
#include "data_manager.h"
#include "structures.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h>

// Número máximo de clientes que o servidor pode gerir simultaneamente
#define MAX_TCP_CLIENTS 10

#define GROUP_NUMBER 66
#define DEFAULT_PORT (58000 + GROUP_NUMBER)


int main(int argc, char *argv[]) {
    int opt;
    int port = DEFAULT_PORT;
    bool verbose = false;

    // parsing argumentos
    while ((opt = getopt(argc, argv, "p:v")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'v':
                verbose = true;
                break;
            default:
                fprintf(stderr, "Uso: %s [-p ESport] [-v]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    printf("Servidor de Eventos (ES) a iniciar...\n");
    if (verbose) {
        printf("VERBOSE SERVER.C: Verbose mode enabled.\n");
    }

    // estado global do servidor
    ServerState server_data;
    server_data.next_eid = 1;

    // diretorias de persistência
    mkdir("USERS", 0700);
    mkdir("EVENTS", 0700);

    // carregar next_eid de ficheiro (se existir)
    char eid_file_path[64];
    snprintf(eid_file_path, sizeof(eid_file_path), "EVENTS/eid.dat");
    FILE *eid_file = fopen(eid_file_path, "r");
    if (eid_file != NULL) {
        if (fscanf(eid_file, "%d", &server_data.next_eid) != 1) {
            fprintf(stderr, "Erro ao ler next_eid de %s. A usar 1.\n", eid_file_path);
            server_data.next_eid = 1;
        }
        fclose(eid_file);
        if (verbose) {
            printf("VERBOSE SERVER.C: Loaded next_eid from %s: %d\n", eid_file_path, server_data.next_eid);
        }
    } else {
        if (verbose) {
            printf("VERBOSE SERVER.C: File %s not found. Initializing next_eid to 1.\n", eid_file_path);
        }
    }

    // criação socket UDP
    int udp_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd == -1) {
        handle_error("Erro ao criar socket UDP");
    }

    // binding
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);

    if (bind(udp_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        handle_error("Erro no bind do socket UDP");
    }

    printf("Servidor UDP a escutar na porta %d\n", port);

    // criar Socket TCP de escuta
    int tcp_fd;
    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) {
        handle_error("Erro ao criar socket TCP");
    }

    // associar o socket TCP à mesma porta
    if (bind(tcp_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        handle_error("Erro no bind do socket TCP");
    }

    // colocar o socket em modo de escuta
    if (listen(tcp_fd, 5) == -1) {
        handle_error("Erro no listen do socket TCP");
    }

    printf("Servidor TCP a escutar na porta %d\n", port);

    // integrar select() e gerir conexões TCP ativas
    fd_set read_fds;
    int max_fd_current;

    // array para guardar os descritores de ficheiro dos sockets TCP dos clientes ativos
    int client_tcp_fds[MAX_TCP_CLIENTS];
    for (int i = 0; i < MAX_TCP_CLIENTS; i++) {
        client_tcp_fds[i] = 0;
    }

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(udp_fd, &read_fds);
        FD_SET(tcp_fd, &read_fds);
        
        max_fd_current = (udp_fd > tcp_fd) ? udp_fd : tcp_fd;

        // adicionar todos os sockets TCP de clientes ativos ao conjunto
        for (int i = 0; i < MAX_TCP_CLIENTS; i++) {
            if (client_tcp_fds[i] > 0) {
                FD_SET(client_tcp_fds[i], &read_fds);
                if (client_tcp_fds[i] > max_fd_current) {
                    max_fd_current = client_tcp_fds[i];
                }
            }
        }

        // bloquear até que haja atividade num dos sockets monitorizados
        if (select(max_fd_current + 1, &read_fds, NULL, NULL, NULL) < 0) {
            handle_error("Erro no select");
        }

        // verificar se há atividade no socket UDP
        if (FD_ISSET(udp_fd, &read_fds)) {
            char buffer[1024];
            client_len = sizeof(client_addr);

            ssize_t n = recvfrom(udp_fd, buffer, sizeof(buffer) - 1, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
            if (n > 0) {
                buffer[n] = '\0';
                process_udp_request(udp_fd, &client_addr, buffer, &server_data, verbose);
            }
        }

        // verificar se há atividade no socket TCP de escuta
        if (FD_ISSET(tcp_fd, &read_fds)) {
            int new_tcp_fd;
            client_len = sizeof(client_addr);
            new_tcp_fd = accept(tcp_fd, (struct sockaddr*)&client_addr, &client_len);
            if (new_tcp_fd < 0) {
                perror("Erro no accept");
            }

            else {
                // encontrar um slot vazio no array client_tcp_fds
                int i;
                for (i = 0; i < MAX_TCP_CLIENTS; i++) {
                    if (client_tcp_fds[i] == 0) {
                        client_tcp_fds[i] = new_tcp_fd;
                        if (verbose) {
                            printf("VERBOSE SERVER.C: New TCP connection accepted from %s:%d (fd: %d).\n",
                                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), new_tcp_fd);
                        }
                        break;
                    }
                }
                if (i == MAX_TCP_CLIENTS) {
                    fprintf(stderr, "Maximum number of TCP clients reached. Connection rejected (fd: %d).\n", new_tcp_fd);
                    close(new_tcp_fd);
                }
            }
        }

        // verificar se há atividade nos sockets TCP dos clientes ativos
        for (int i = 0; i < MAX_TCP_CLIENTS; i++) {
            if (client_tcp_fds[i] > 0 && FD_ISSET(client_tcp_fds[i], &read_fds)) {
                char tcp_buffer[1024];
                memset(tcp_buffer, 0, sizeof(tcp_buffer));
                ssize_t bytes_read = read(client_tcp_fds[i], tcp_buffer, sizeof(tcp_buffer) - 1);

                // conexão fechada pelo cliente ou erro
                if (bytes_read <= 0) {
                    if (bytes_read == 0) {
                        if (verbose) {
                            printf("VERBOSE SERVER.C: TCP client (fd: %d) disconnected.\n", client_tcp_fds[i]);
                        }
                    } else {
                        perror("Erro ao ler do socket TCP do cliente");
                    }
                    close(client_tcp_fds[i]);
                    client_tcp_fds[i] = 0;
                } else {
                    if (verbose) {
                        printf("VERBOSE SERVER.C: Received data from TCP client (fd: %d), processing...\n", client_tcp_fds[i]);
                    }

                    char response_buffer[8192];
                    memset(response_buffer, 0, sizeof(response_buffer));
                    process_tcp_request(client_tcp_fds[i], tcp_buffer, bytes_read, &server_data, verbose, response_buffer, sizeof(response_buffer));

                    if (strlen(response_buffer) > 0) {
                        write(client_tcp_fds[i], response_buffer, strlen(response_buffer));
                    }

                    // shutdown para garantir que todos os dados são enviados antes de fechar
                    shutdown(client_tcp_fds[i], SHUT_WR);
                    close(client_tcp_fds[i]);
                    client_tcp_fds[i] = 0;
                }
            }
        }
    }
    close(udp_fd);
    close(tcp_fd);
    return 0;
}
