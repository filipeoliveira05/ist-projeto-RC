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
#include <sys/select.h>
#include <sys/stat.h>

// (ALTERAR) Número máximo de clientes TCP que o servidor pode gerir simultaneamente
#define MAX_TCP_CLIENTS 10

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

/*
 * Adiciona um novo evento à lista ligada de eventos do servidor.
 */
Event* add_event(ServerState *state, const char *owner_uid, const char *name, const char *date, int total_seats, const char *filename) {
    Event* new_event = (Event*)malloc(sizeof(Event));
    if (new_event == NULL) {
        handle_error("Erro ao alocar memória para novo evento");
    }

    new_event->eid = state->next_eid++;
    strncpy(new_event->owner_uid, owner_uid, sizeof(new_event->owner_uid) - 1);
    strncpy(new_event->name, name, sizeof(new_event->name) - 1);
    new_event->name[sizeof(new_event->name) - 1] = '\0'; // Garantir terminação nula
    strncpy(new_event->date, date, sizeof(new_event->date) - 1);
    new_event->date[sizeof(new_event->date) - 1] = '\0'; // Garantir terminação nula
    new_event->total_seats = total_seats;
    strncpy(new_event->filename, filename, sizeof(new_event->filename) - 1);

    new_event->reserved_seats = 0;
    new_event->state = ACTIVE;
    new_event->reservations = NULL;
    new_event->next = state->events;
    state->events = new_event;
    return new_event;
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
            char buffer[1024];
            char response_buffer[1024];
            char command[4];
            char uid_str[7];
            char password_str[9];
            client_len = sizeof(client_addr);

            ssize_t n = recvfrom(udp_fd, buffer, sizeof(buffer) - 1, 0,
                                 (struct sockaddr*)&client_addr, &client_len);

            if (n > 0) {
                buffer[n] = '\0';

                if (verbose) {
                    printf("Recebido pedido UDP de %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    printf("Mensagem: %s", buffer);
                }

                // Toda a lógica de processamento de comandos UDP que já existia
                if (sscanf(buffer, "%3s %6s %8s\n", command, uid_str, password_str) == 3) {
                    if (strcmp(command, "LIN") == 0) {
                        User* user = find_user_by_uid(&server_data, uid_str);
                        if (user != NULL) {
                            if (strcmp(user->password, password_str) == 0) {
                                user->is_logged_in = true;
                                strcpy(response_buffer, "RLI OK\n");
                                if (verbose) printf("User %s logado com sucesso.\n", uid_str);
                            } else {
                                strcpy(response_buffer, "RLI NOK\n");
                                if (verbose) printf("Tentativa de login falhou para %s: password incorreta.\n", uid_str);
                            }
                        } else {
                            add_user(&server_data, uid_str, password_str);
                            strcpy(response_buffer, "RLI REG\n");
                            if (verbose) printf("Novo user %s registado e logado.\n", uid_str);
                        }
                    } else if (strcmp(command, "LOU") == 0) {
                        User* user = find_user_by_uid(&server_data, uid_str);
                        if (user != NULL) {
                            if (strcmp(user->password, password_str) == 0) {
                                if (user->is_logged_in) {
                                    user->is_logged_in = false;
                                    strcpy(response_buffer, "RLO OK\n");
                                    if (verbose) printf("User %s fez logout com sucesso.\n", uid_str);
                                } else {
                                    strcpy(response_buffer, "RLO NOK\n");
                                    if (verbose) printf("User %s tentou logout mas não estava logado.\n", uid_str);
                                }
                            } else {
                                strcpy(response_buffer, "RLO WRP\n");
                                if (verbose) printf("Tentativa de logout falhou para %s: password incorreta.\n", uid_str);
                            }
                        } else {
                            strcpy(response_buffer, "RLO UNR\n");
                            if (verbose) printf("Tentativa de logout falhou: user %s não registado.\n", uid_str);
                        }
                    } else if (strcmp(command, "UNR") == 0) {
                        User* user = find_user_by_uid(&server_data, uid_str);
                        if (user != NULL) {
                            if (strcmp(user->password, password_str) == 0) {
                                if (user->is_logged_in) {
                                    remove_user(&server_data, uid_str);
                                    strcpy(response_buffer, "RUR OK\n");
                                    if (verbose) printf("User %s removido com sucesso.\n", uid_str);
                                } else {
                                    strcpy(response_buffer, "RUR NOK\n");
                                    if (verbose) printf("Tentativa de unregister falhou para %s: user não estava logado.\n", uid_str);
                                }
                            } else {
                                strcpy(response_buffer, "RUR WRP\n");
                                if (verbose) printf("Tentativa de unregister falhou para %s: password incorreta.\n", uid_str);
                            }
                        } else {
                            strcpy(response_buffer, "RUR UNR\n");
                            if (verbose) printf("Tentativa de unregister falhou: user %s não registado.\n", uid_str);
                        }
                    } else {
                        strcpy(response_buffer, "RLI ERR\n");
                        if (verbose) printf("Comando UDP desconhecido ou não implementado: %s\n", command);
                    }
                } else {
                    strcpy(response_buffer, "RLI ERR\n");
                    if (verbose) printf("Erro de sintaxe no pedido UDP: %s", buffer);
                }

                ssize_t sent_bytes = sendto(udp_fd, response_buffer, strlen(response_buffer), 0,
                                            (struct sockaddr*)&client_addr, client_len);
                if (sent_bytes == -1) {
                    perror("Erro ao enviar resposta UDP");
                } else if (verbose) {
                    printf("Resposta UDP enviada para %s:%d: %s", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), response_buffer);
                }
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

                    char response_msg[128];

                    // --- Implementar create (CRE/RCE) ---
                    if (strncmp(tcp_buffer, "CRE", 3) == 0) {
                        char uid[7], password[9], name[11], date[17], fname[25];
                        int attendance_size;
                        long fsize;

                        // 1. Analisar o cabeçalho de texto
                        int num_parsed = sscanf(tcp_buffer, "CRE %6s %8s %10s %16s %d %24s %ld",
                                                uid, password, name, date, &attendance_size, fname, &fsize);

                        User* user = find_user_by_uid(&server_data, uid);

                        // 2. Validar o pedido
                        if (num_parsed < 7) {
                            snprintf(response_msg, sizeof(response_msg), "RCE ERR\n");
                        } else if (user == NULL || strcmp(user->password, password) != 0) {
                            snprintf(response_msg, sizeof(response_msg), "RCE WRP\n");
                        } else if (!user->is_logged_in) {
                            snprintf(response_msg, sizeof(response_msg), "RCE NLG\n");
                        } else {
                            // 3. Receber e guardar o ficheiro
                            char event_dir[32];
                            char event_filepath[64];
                            snprintf(event_dir, sizeof(event_dir), "EVENTS/%03d", server_data.next_eid);
                            mkdir("EVENTS", 0777); // Cria o diretório principal se não existir
                            mkdir(event_dir, 0777); // Cria o diretório específico do evento
                            snprintf(event_filepath, sizeof(event_filepath), "%s/%s", event_dir, fname);

                            FILE *file = fopen(event_filepath, "wb");
                            if (file == NULL) {
                                perror("Erro ao criar ficheiro do evento no servidor");
                                snprintf(response_msg, sizeof(response_msg), "RCE NOK\n");
                            } else {
                                // Lógica robusta para encontrar o início dos dados do ficheiro.
                                char *file_data_start = tcp_buffer;
                                // O cabeçalho "CRE UID password name date size fname fsize " tem 8 campos, logo 7 espaços antes do Fsize e 8 espaços antes do Fdata.
                                int spaces_to_find = 8;
                                while (spaces_to_find > 0 && (file_data_start = strchr(file_data_start, ' ')) != NULL) {
                                    file_data_start++; // Avança para depois do espaço encontrado
                                    spaces_to_find--;
                                }

                                if (file_data_start == NULL) { /* Lidar com erro de formato se necessário */ }

                                long initial_data_len = bytes_read - (file_data_start - tcp_buffer);
                                fwrite(file_data_start, 1, initial_data_len, file);
                                long remaining_bytes = fsize - initial_data_len;

                                // Ler o resto do ficheiro do socket
                                while (remaining_bytes > 0) {
                                    bytes_read = read(client_tcp_fds[i], tcp_buffer, sizeof(tcp_buffer));
                                    if (bytes_read <= 0) break;
                                    fwrite(tcp_buffer, 1, bytes_read, file);
                                    remaining_bytes -= bytes_read;
                                }
                                fclose(file);

                                // 4. Criar o evento e preparar a resposta
                                Event* new_event = add_event(&server_data, uid, name, date, attendance_size, fname);
                                snprintf(response_msg, sizeof(response_msg), "RCE OK %03d\n", new_event->eid);
                                if (verbose) printf("Evento %03d criado por %s.\n", new_event->eid, uid);
                            }
                        }
                    } else if (strncmp(tcp_buffer, "LST", 3) == 0) {
                        // --- Implementar list (LST/RLS) ---
                        if (server_data.events == NULL) {
                            if (verbose) printf("Nenhum evento para listar. A enviar RLS NOK.\n");
                            snprintf(response_msg, sizeof(response_msg), "RLS NOK\n");
                            if (verbose) {
                                printf("Resposta TCP enviada para fd %d: %s", client_tcp_fds[i], response_msg);
                            }
                            write(client_tcp_fds[i], response_msg, strlen(response_msg));
                        } else {
                            // Enviar o cabeçalho da resposta
                            snprintf(response_msg, sizeof(response_msg), "RLS OK ");
                            write(client_tcp_fds[i], response_msg, strlen(response_msg));
                            // Iterar sobre todos os eventos e enviar a informação de cada um
                            Event* current = server_data.events;
                            while (current != NULL) {
                                // Formato: EID name state event_date
                                // O enunciado do cliente pede para mostrar EID, nome e data. Vamos enviar tudo.
                                snprintf(response_msg, sizeof(response_msg), "%03d %s %d %s\n",
                                         current->eid, current->name, current->state, current->date);
                                write(client_tcp_fds[i], response_msg, strlen(response_msg));
                                current = current->next;
                            }
                            // Enviar um \n final para indicar o fim da lista, como especificado no enunciado.
                            write(client_tcp_fds[i], "\n", 1);
                            if (verbose) printf("Lista de eventos enviada para fd %d.\n", client_tcp_fds[i]);
                        }
                        close(client_tcp_fds[i]);
                        client_tcp_fds[i] = 0;
                        break; 
                    } else {
                        // Comando TCP desconhecido
                        snprintf(response_msg, sizeof(response_msg), "ERR\n");
                    }

                    // Enviar resposta e fechar conexão
                    ssize_t bytes_sent = write(client_tcp_fds[i], response_msg, strlen(response_msg));
                    if (bytes_sent == -1) {
                        perror("Erro ao escrever para o socket TCP do cliente");
                    } else if (verbose) {
                        printf("Resposta TCP enviada para fd %d: %s", client_tcp_fds[i], response_msg);
                    }

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
