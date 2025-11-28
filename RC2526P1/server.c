// Define a fonte POSIX para ter acesso a getopt() e optarg no VS Code
#define _POSIX_C_SOURCE 200809L

#include "server_logic.h" // Inclui a lógica de processamento
#include "data_manager.h" // Inclui as funções de dados (para inicializar ServerState)
#include "structures.h"   // Continua a ser necessário para ServerState
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

// (ALTERAR) Número máximo de clientes TCP que o servidor pode gerir simultaneamente
#define MAX_TCP_CLIENTS 10

#define GROUP_NUMBER 66
#define DEFAULT_PORT (58000 + GROUP_NUMBER)


int main(int argc, char *argv[]) {
    int opt;
    int port = DEFAULT_PORT;
    bool verbose = false;

    // --- Fase 1: Parsing de Argumentos ---
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
        printf("Modo Verbose ativado.\n");
    }

    // Inicializar o estado global do servidor
    ServerState server_data;
    server_data.users = NULL;
    server_data.events = NULL;
    server_data.next_eid = 1; // EIDs começam em 1

    // --- Fase 2: Criação do Socket UDP ---
    int udp_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;

    udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd == -1) {
        handle_error("Erro ao criar socket UDP");
    }

    // --- Fase 3: Binding ---
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); // Aceita conexões de qualquer IP
    server_addr.sin_port = htons(port);

    if (bind(udp_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        handle_error("Erro no bind do socket UDP");
    }

    printf("Servidor UDP a escutar na porta %d\n", port);

    // --- Fase 3.1: Criar Socket TCP de Escuta ---
    int tcp_fd;
    tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) {
        handle_error("Erro ao criar socket TCP");
    }

    // Associar o socket TCP à mesma porta
    if (bind(tcp_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        handle_error("Erro no bind do socket TCP");
    }

    // Colocar o socket em modo de escuta
    if (listen(tcp_fd, 5) == -1) { // O 5 é o backlog, o número de conexões pendentes
        handle_error("Erro no listen do socket TCP");
    }

    printf("Servidor TCP a escutar na porta %d\n", port);

    // --- Fase 3.2 e 3.3: Integrar select() e Gerir Conexões TCP Ativas ---
    fd_set read_fds;
    int max_fd_current; // O maior descritor de ficheiro atual para select()

    // Array para guardar os descritores de ficheiro dos sockets TCP dos clientes ativos
    int client_tcp_fds[MAX_TCP_CLIENTS];
    for (int i = 0; i < MAX_TCP_CLIENTS; i++) {
        client_tcp_fds[i] = 0; // Inicializa todos os slots como livres (0 é um fd inválido)
    }

    while (1) {
        // Limpar o conjunto de descritores e adicionar os sockets de escuta
        FD_ZERO(&read_fds);
        FD_SET(udp_fd, &read_fds);
        FD_SET(tcp_fd, &read_fds);
        
        // Determinar o maior descritor de ficheiro para o select()
        max_fd_current = (udp_fd > tcp_fd) ? udp_fd : tcp_fd;

        // Adicionar todos os sockets TCP de clientes ativos ao conjunto e atualizar max_fd_current
        for (int i = 0; i < MAX_TCP_CLIENTS; i++) {
            if (client_tcp_fds[i] > 0) { // Se o slot estiver em uso
                FD_SET(client_tcp_fds[i], &read_fds);
                if (client_tcp_fds[i] > max_fd_current) {
                    max_fd_current = client_tcp_fds[i];
                }
            }
        }

        // Bloquear até que haja atividade num dos sockets monitorizados
        if (select(max_fd_current + 1, &read_fds, NULL, NULL, NULL) < 0) {
            handle_error("Erro no select");
        }

        // Verificar se há atividade no socket UDP
        if (FD_ISSET(udp_fd, &read_fds)) {
            char buffer[1024]; // Buffer para o pedido
            client_len = sizeof(client_addr);

            ssize_t n = recvfrom(udp_fd, buffer, sizeof(buffer) - 1, 0,
                                 (struct sockaddr*)&client_addr, &client_len);
            if (n > 0) {
                buffer[n] = '\0';
                process_udp_request(udp_fd, &client_addr, buffer, &server_data, verbose);
            }
        }

        // Verificar se há atividade no socket TCP de escuta
        if (FD_ISSET(tcp_fd, &read_fds)) {
            int new_tcp_fd;
            client_len = sizeof(client_addr); // client_addr e client_len já estão definidos
            new_tcp_fd = accept(tcp_fd, (struct sockaddr*)&client_addr, &client_len);
            if (new_tcp_fd < 0) {
                perror("Erro no accept"); // Usar perror para erros de accept
            }

            else {
                // Encontrar um slot vazio no array client_tcp_fds
                int i;
                for (i = 0; i < MAX_TCP_CLIENTS; i++) {
                    if (client_tcp_fds[i] == 0) { // Slot encontrado
                        client_tcp_fds[i] = new_tcp_fd;
                        if (verbose) {
                            printf("Nova conexão TCP aceite de %s:%d (fd: %d).\n",
                                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), new_tcp_fd);
                        }
                        break;
                    }
                }
                if (i == MAX_TCP_CLIENTS) { // Não há slots disponíveis
                    fprintf(stderr, "Número máximo de clientes TCP atingido. Conexão rejeitada (fd: %d).\n", new_tcp_fd);
                    close(new_tcp_fd); // Fecha a nova conexão imediatamente
                }
            }
        }

        // Verificar se há atividade nos sockets TCP dos clientes ativos
        for (int i = 0; i < MAX_TCP_CLIENTS; i++) {
            if (client_tcp_fds[i] > 0 && FD_ISSET(client_tcp_fds[i], &read_fds)) {
                char tcp_buffer[1024]; // Buffer para dados TCP
                ssize_t bytes_read = read(client_tcp_fds[i], tcp_buffer, sizeof(tcp_buffer) - 1);

                if (bytes_read <= 0) { // Conexão fechada pelo cliente ou erro
                    if (bytes_read == 0) { // Cliente fechou a conexão graciosamente
                        if (verbose) {
                            printf("Cliente TCP (fd: %d) desconectou-se.\n", client_tcp_fds[i]);
                        }
                    } else { // Erro na leitura
                        perror("Erro ao ler do socket TCP do cliente");
                    }
                    close(client_tcp_fds[i]); // Fecha o socket
                    client_tcp_fds[i] = 0; // Marca o slot como livre
                } else {
                    tcp_buffer[bytes_read] = '\0'; // Termina a string lida com null
                    if (verbose) {
                        // Imprime apenas o início do buffer para não poluir o log com dados de ficheiro
                        printf("Recebido pedido TCP de fd %d, a processar...\n", client_tcp_fds[i]);
                    }

                    process_tcp_request(client_tcp_fds[i], tcp_buffer, bytes_read, &server_data, verbose);
                    close(client_tcp_fds[i]);
                    client_tcp_fds[i] = 0; // Marca o slot como livre
                    break; // Sai do loop 'for' para reavaliar os fds no próximo ciclo do select
                }
            }
        }
    }
    close(udp_fd);
    close(tcp_fd);
    return 0;
}
