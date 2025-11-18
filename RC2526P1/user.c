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

// --- Estado Global do Utilizador ---
// Guarda a informação do utilizador atualmente logado.
char current_uid[7] = {0};
char current_password[9] = {0};
bool is_logged_in = false;

void handle_error(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[]) {
    int opt;
    char *server_ip = "127.0.0.1"; // IP padrão é localhost
    int server_port = DEFAULT_PORT;

    // --- Parsing de Argumentos ---
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

    // --- Configuração do Socket e Endereço do Servidor ---
    int udp_fd;
    struct sockaddr_in server_addr;
    struct hostent *host;

    host = gethostbyname(server_ip);
    if (host == NULL) {
        fprintf(stderr, "ERRO, não foi possível encontrar o host '%s'\n", server_ip);
        exit(1);
    }

    char command_buffer[2048];
    // --- Loop de Comandos ---
    while (1) {
        printf("> ");
        fflush(stdout); // Garantir que o prompt aparece antes do input do utilizador

        if (fgets(command_buffer, sizeof(command_buffer), stdin) == NULL) {
            // Atingido o fim do input (Ctrl+D), sair do loop
            printf("\nFim de input. A terminar a aplicação.\n");
            break;
        }

        char command[20], arg1[20], arg2[20];
        int num_args = sscanf(command_buffer, "%s %s %s", command, arg1, arg2);

        if (num_args <= 0) { // Nenhum comando foi inserido (apenas Enter)
            continue;
        }

        if (strcmp(command, "login") == 0 && num_args == 3) {
            if (is_logged_in) {
                printf("Já existe um utilizador com sessão iniciada. Por favor, faça logout primeiro.\n");
                continue;
            }

            // --- Implementar login ---
            udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (udp_fd == -1) handle_error("Erro ao criar socket UDP");

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            memcpy((void*)&server_addr.sin_addr, host->h_addr_list[0], host->h_length);
            server_addr.sin_port = htons(server_port);

            char request_buffer[128];
            char response_buffer[128];

            // Formatar a mensagem UDP
            snprintf(request_buffer, sizeof(request_buffer), "LIN %s %s\n", arg1, arg2);

            // Enviar a mensagem para o servidor
            sendto(udp_fd, request_buffer, strlen(request_buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

            // Esperar pela resposta do servidor
            socklen_t addr_len = sizeof(server_addr);
            ssize_t n = recvfrom(udp_fd, response_buffer, sizeof(response_buffer) - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
            
            if (n > 0) {
                response_buffer[n] = '\0';
                // Analisar a resposta
                if (strncmp(response_buffer, "RLI OK", 6) == 0) {
                    printf("Login bem-sucedido.\n");
                    is_logged_in = true;
                    strncpy(current_uid, arg1, sizeof(current_uid) - 1);
                    strncpy(current_password, arg2, sizeof(current_password) - 1);
                } else if (strncmp(response_buffer, "RLI REG", 7) == 0) {
                    printf("Novo utilizador registado com sucesso.\n");
                    is_logged_in = true;
                    strncpy(current_uid, arg1, sizeof(current_uid) - 1);
                    strncpy(current_password, arg2, sizeof(current_password) - 1);
                } else if (strncmp(response_buffer, "RLI NOK", 7) == 0) {
                    printf("Login falhou: password incorreta ou utilizador não existe.\n");
                } else {
                    printf("Resposta inesperada do servidor: %s", response_buffer);
                }
            } else {
                printf("Não foi possível obter resposta do servidor.\n");
            }

            close(udp_fd);

        } else if (strcmp(command, "logout") == 0 && num_args == 1) {
            if (!is_logged_in) {
                printf("Não há sessão iniciada.\n");
                continue;
            }

            // --- Implementar logout ---
            udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (udp_fd == -1) handle_error("Erro ao criar socket UDP");

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            memcpy((void*)&server_addr.sin_addr, host->h_addr_list[0], host->h_length);
            server_addr.sin_port = htons(server_port);

            char request_buffer[128];
            char response_buffer[128];

            snprintf(request_buffer, sizeof(request_buffer), "LOU %s %s\n", current_uid, current_password);
            sendto(udp_fd, request_buffer, strlen(request_buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

            socklen_t addr_len = sizeof(server_addr);
            ssize_t n = recvfrom(udp_fd, response_buffer, sizeof(response_buffer) - 1, 0, (struct sockaddr*)&server_addr, &addr_len);

            if (n > 0) {
                response_buffer[n] = '\0';
                if (strncmp(response_buffer, "RLO OK", 6) == 0) {
                    printf("Logout bem-sucedido.\n");
                    is_logged_in = false;
                    memset(current_uid, 0, sizeof(current_uid));
                    memset(current_password, 0, sizeof(current_password));
                } else {
                    printf("Logout falhou. Resposta do servidor: %s", response_buffer);
                }
            } else {
                printf("Não foi possível obter resposta do servidor.\n");
            }
            close(udp_fd);

        } else if (strcmp(command, "unregister") == 0 && num_args == 1) {
            if (!is_logged_in) {
                printf("Não há sessão iniciada para anular o registo.\n");
                continue;
            }

            // --- Implementar unregister ---
            udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (udp_fd == -1) handle_error("Erro ao criar socket UDP");

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            memcpy((void*)&server_addr.sin_addr, host->h_addr_list[0], host->h_length);
            server_addr.sin_port = htons(server_port);

            char request_buffer[128], response_buffer[128];
            snprintf(request_buffer, sizeof(request_buffer), "UNR %s %s\n", current_uid, current_password);
            sendto(udp_fd, request_buffer, strlen(request_buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

            // A lógica de resposta para unregister é idêntica à de logout, apenas muda a mensagem de sucesso
            // e o estado do cliente é limpo da mesma forma.
            // Para um código mais limpo, isto poderia ser abstraído para uma função.
            // Por agora, vamos manter explícito para clareza.
            socklen_t addr_len = sizeof(server_addr);
            ssize_t n = recvfrom(udp_fd, response_buffer, sizeof(response_buffer) - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
            if (n > 0) {
                response_buffer[n] = '\0';
                if (strncmp(response_buffer, "RUR OK", 6) == 0) {
                    printf("Registo anulado com sucesso.\n");
                    is_logged_in = false;
                    memset(current_uid, 0, sizeof(current_uid));
                    memset(current_password, 0, sizeof(current_password));
                } else {
                    printf("Anulação de registo falhou. Resposta do servidor: %s", response_buffer);
                }
            } else {
                printf("Não foi possível obter resposta do servidor.\n");
            }
            close(udp_fd);

        } else if (strcmp(command, "exit") == 0) {
            if (is_logged_in) {
                printf("Utilizador ainda com sessão iniciada. Por favor, execute o comando 'logout' primeiro.\n");
            } else {
                printf("A terminar a aplicação.\n");
                break; // Sai do loop while(1)
            }
        } else {
            printf("Comando desconhecido ou número de argumentos inválido.\n");
        }
    }

    return 0;
}
