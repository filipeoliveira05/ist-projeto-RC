// Define a fonte POSIX para ter acesso a getopt() e optarg no VS Code
#define _POSIX_C_SOURCE 200809L

#include "structures.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> // Para gethostbyname

// (ALTERAR) Definir o número do grupo para a porta padrão
#define GROUP_NUMBER 25
#define DEFAULT_PORT (58000 + GROUP_NUMBER)

int main(int argc, char *argv[]) {
    int opt;
    char *server_ip = "127.0.0.1"; // IP padrão é localhost
    int server_port = DEFAULT_PORT;

    // --- Fase 2.1: Parsing de Argumentos ---
    // Usamos getopt para processar os argumentos -n e -p
    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
        switch (opt) {
            case 'n':
                server_ip = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Uso: %s [-n ESIP] [-p ESport]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    printf("Aplicação de Utilizador a iniciar...\n");
    printf("A ligar ao Servidor de Eventos em %s:%d\n", server_ip, server_port);

    // --- Fase 2.2: Loop de Comandos ---
    char command_buffer[2048];
    while (1) {
        printf("> ");
        fflush(stdout); // Garantir que o prompt aparece antes do input do utilizador

        if (fgets(command_buffer, sizeof(command_buffer), stdin) == NULL) {
            // Atingido o fim do input (Ctrl+D), sair do loop
            printf("\nFim de input. A terminar a aplicação.\n");
            break;
        }

        // Por agora, apenas imprimimos o comando lido.
        // A lógica para "exit" e outros comandos será adicionada aqui.
        printf("Comando lido: %s", command_buffer);
    }

    return 0;
}
