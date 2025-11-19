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

// (ALTERAR) Definir o número do grupo para a porta padrão
#define GROUP_NUMBER 25
#define DEFAULT_PORT (58000 + GROUP_NUMBER)

void handle_error(const char *msg) {
    perror(msg);
    exit(1);
}

// --- Funções Auxiliares para Gestão de Utilizadores ---

/*
 * Remove um user da linked list de users do servidor.
 */
void remove_user(ServerState *state, const char *uid) {
    User *current = state->users, *prev = NULL;

    // Se o user a remover for o primeiro da lista
    if (current != NULL && strcmp(current->uid, uid) == 0) {
        state->users = current->next;
        free(current);
        return;
    }

    // Procura o user na lista
    while (current != NULL && strcmp(current->uid, uid) != 0) {
        prev = current;
        current = current->next;
    }

    // Se o user não foi encontrado
    if (current == NULL) return;

    // Remove o user da linked list
    prev->next = current->next;

    free(current); // Liberta a memória alocada ao user
}

/*
 * Procura um user na linked list pelo seu UID.
 * Retorna um pointer para o user se encontrado, ou NULL caso contrário.
 */
User* find_user_by_uid(ServerState *state, const char *uid) {
    User* current = state->users;
    while (current != NULL) {
        if (strcmp(current->uid, uid) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/*
 * Adiciona um novo user à linked list de users do servidor.
 * Retorna um pointer para o novo user criado.
 */
User* add_user(ServerState *state, const char *uid, const char *password) {
    User* new_user = (User*)malloc(sizeof(User));
    if (new_user == NULL) {
        handle_error("Erro ao alocar memória para novo user");
    }

    strncpy(new_user->uid, uid, sizeof(new_user->uid) - 1);
    new_user->uid[sizeof(new_user->uid) - 1] = '\0';

    strncpy(new_user->password, password, sizeof(new_user->password) - 1);
    new_user->password[sizeof(new_user->password) - 1] = '\0';

    new_user->is_logged_in = true; // Novo user é automaticamente logado
    new_user->next = state->users; // Adiciona no início da linked list
    state->users = new_user;

    return new_user;
}

// ----------------------------------------------------


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

    // --- Fase 4: Loop Principal e recvfrom() ---
    while (1) {
        char buffer[1024];
        char response_buffer[1024]; // Buffer para a resposta
        char command[4]; // Para "LIN", "LOU", "UNR", etc.
        char uid_str[7];
        char password_str[9];
        client_len = sizeof(client_addr);

        ssize_t n = recvfrom(udp_fd, buffer, sizeof(buffer) - 1, 0,
                             (struct sockaddr*)&client_addr, &client_len);

        if (n > 0) {
            buffer[n] = '\0'; // Garantir que a string é terminada

            if (verbose) {
                printf("Recebido pedido de %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                printf("Mensagem UDP recebida: %s", buffer);
            }

            // Analisar o comando recebido
            // Usamos sscanf para tentar extrair o comando e os argumentos
            // Note que o '\n' no final da string é importante para o sscanf
            if (sscanf(buffer, "%3s %6s %8s\n", command, uid_str, password_str) == 3) {
                if (strcmp(command, "LIN") == 0) {
                    // --- Implementar login (LIN/RLI) ---
                    User* user = find_user_by_uid(&server_data, uid_str);

                    if (user != NULL) {
                        // Utilizador existe
                        if (strcmp(user->password, password_str) == 0) {
                            // Password correta
                            user->is_logged_in = true;
                            strcpy(response_buffer, "RLI OK\n");
                            if (verbose) printf("User %s logado com sucesso.\n", uid_str);
                        } else {
                            // Password incorreta
                            strcpy(response_buffer, "RLI NOK\n");
                            if (verbose) printf("Tentativa de login falhou para %s: password incorreta.\n", uid_str);
                        }
                    } else {
                        // Utilizador não existe, registar novo
                        add_user(&server_data, uid_str, password_str);
                        strcpy(response_buffer, "RLI REG\n");
                        if (verbose) printf("Novo user %s registado e logado.\n", uid_str);
                    }
                
                } else if (strcmp(command, "LOU") == 0) {
                    // --- Implementar logout (LOU/RLO) ---
                    User* user = find_user_by_uid(&server_data, uid_str);

                    if (user != NULL) {
                        // User existe
                        if (strcmp(user->password, password_str) == 0) {
                            // Password correta
                            if (user->is_logged_in) {
                                // User está logado, fazer logout
                                user->is_logged_in = false;
                                strcpy(response_buffer, "RLO OK\n");
                                if (verbose) printf("User %s fez logout com sucesso.\n", uid_str);
                            } else {
                                // User não está logado
                                strcpy(response_buffer, "RLO NOK\n");
                                if (verbose) printf("User %s tentou logout mas não estava logado.\n", uid_str);
                            }
                        } else {
                            // Password incorreta
                            strcpy(response_buffer, "RLO WRP\n");
                            if (verbose) printf("Tentativa de logout falhou para %s: password incorreta.\n", uid_str);
                        }
                    } else {
                        // User não existe
                        strcpy(response_buffer, "RLO UNR\n");
                        if (verbose) printf("Tentativa de logout falhou: user %s não registado.\n", uid_str);
                    }
                
                } else if (strcmp(command, "UNR") == 0) {
                    // --- Implementar unregister (UNR/RUR) ---
                    User* user = find_user_by_uid(&server_data, uid_str);

                    if (user != NULL) {
                        // User existe
                        if (strcmp(user->password, password_str) == 0) {
                            // Password correta
                            if (user->is_logged_in) {
                                // User está logado, pode ser removido
                                remove_user(&server_data, uid_str);
                                strcpy(response_buffer, "RUR OK\n");
                                if (verbose) printf("User %s removido com sucesso.\n", uid_str);
                            } else {
                                // User não está logado
                                strcpy(response_buffer, "RUR NOK\n");
                                if (verbose) printf("Tentativa de unregister falhou para %s: user não estava logado.\n", uid_str);
                            }
                        } else {
                            // Password incorreta
                            strcpy(response_buffer, "RUR WRP\n");
                            if (verbose) printf("Tentativa de unregister falhou para %s: password incorreta.\n", uid_str);
                        }
                    } else {
                        // User não existe
                        strcpy(response_buffer, "RUR UNR\n");
                        if (verbose) printf("Tentativa de unregister falhou: user %s não registado.\n", uid_str);
                    }

                } else {
                    // Outros comandos UDP (LOU, UNR, LME, LMR) serão implementados mais tarde
                    strcpy(response_buffer, "RLI ERR\n"); // Resposta de erro genérica por enquanto
                    if (verbose) printf("Comando UDP desconhecido ou não implementado: %s\n", command);
                }
            } else {
                // Erro de sintaxe no pedido
                strcpy(response_buffer, "RLI ERR\n");
                if (verbose) printf("Erro de sintaxe no pedido UDP: %s", buffer);
            }

            // Enviar a resposta de volta ao cliente
            ssize_t sent_bytes = sendto(udp_fd, response_buffer, strlen(response_buffer), 0,
                                        (struct sockaddr*)&client_addr, client_len);
            if (sent_bytes == -1) {
                perror("Erro ao enviar resposta UDP");
            } else {
                if (verbose) {
                    printf("Resposta UDP enviada para %s:%d: %s", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), response_buffer);
                }
            }

        }
    }

    close(udp_fd);
    close(tcp_fd);
    return 0;
}
