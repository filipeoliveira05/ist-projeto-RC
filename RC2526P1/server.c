#include "structures.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// (ALTERAR) Definir o número do grupo para a porta padrão
#define GROUP_NUMBER 25
#define DEFAULT_PORT (58000 + GROUP_NUMBER)

void handle_error(const char *msg) {
    perror(msg);
    exit(1);
}

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

    // --- Fase 4: Loop Principal e recvfrom() ---
    while (1) {
        char buffer[1024];
        client_len = sizeof(client_addr);

        ssize_t n = recvfrom(udp_fd, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr*)&client_addr, &client_len);

        if (n > 0) {
            buffer[n] = '\0'; // Garantir que a string é terminada

            if (verbose) {
                printf("Recebido pedido de %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            }
            printf("Mensagem UDP recebida: %s", buffer); // O buffer já contém o '\n'
        }
    }

    close(udp_fd);
    return 0;
}
