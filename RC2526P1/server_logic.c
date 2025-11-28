#include "server_logic.h"
#include "data_manager.h" // Precisa do data_manager para manipular os dados
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>

void process_udp_request(int udp_fd, struct sockaddr_in *client_addr, char *buffer, ServerState *server_data, bool verbose) {
    // ... cole aqui toda a lógica de processamento UDP ...
    // (sscanf, if/else para LIN, LOU, UNR, etc.)
    // ... e a lógica de sendto() da resposta.
    char response_buffer[1024];
    char command[4];
    char uid_str[7];
    char password_str[9];
    socklen_t client_len = sizeof(*client_addr);

    if (verbose) {
        printf("Recebido pedido UDP de %s:%d\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port));
        printf("Mensagem: %s", buffer);
    }

    // Toda a lógica de processamento de comandos UDP que já existia
    if (sscanf(buffer, "%3s %6s %8s\n", command, uid_str, password_str) == 3) {
        if (strcmp(command, "LIN") == 0) { // O server_data já é um ponteiro
            User* user = find_user_by_uid(server_data, uid_str);
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
                add_user(server_data, uid_str, password_str);
                strcpy(response_buffer, "RLI REG\n");
                if (verbose) printf("Novo user %s registado e logado.\n", uid_str);
            }
        } else if (strcmp(command, "LOU") == 0) {
            User* user = find_user_by_uid(server_data, uid_str);
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
            User* user = find_user_by_uid(server_data, uid_str);
            if (user != NULL) {
                if (strcmp(user->password, password_str) == 0) {
                    if (user->is_logged_in) {
                        remove_user(server_data, uid_str);
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
                                (struct sockaddr*)client_addr, client_len);
    if (sent_bytes == -1) {
        perror("Erro ao enviar resposta UDP");
    } else if (verbose) {
        printf("Resposta UDP enviada para %s:%d: %s", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), response_buffer);
    }
}

void process_tcp_request(int client_fd, char *tcp_buffer, ssize_t bytes_read, ServerState *server_data, bool verbose) {
    // ... cole aqui toda a lógica de processamento TCP ...
    // (if/else para CRE, LST, etc.)
    // ... e a lógica de write() da resposta.
    // NOTA: Esta função não deve fechar o socket, isso é responsabilidade do loop principal em server.c

    char response_msg[128];

    // --- Implementar create (CRE/RCE) ---
    if (strncmp(tcp_buffer, "CRE", 3) == 0) {
        char uid[7], password[9], name[11], date[11], time[6], fname[25];
        int attendance_size;
        long fsize;

        // 1. Analisar o cabeçalho de texto
        // O formato da data é "dd-mm-yyyy hh:mm". O sscanf com %s para no espaço.
        // Temos de ler a data e a hora em separado.
        int num_parsed = sscanf(tcp_buffer, "CRE %6s %8s %10s %10s %5s %d %24s %ld",
                                uid, password, name, date, time, &attendance_size, fname, &fsize);

        User* user = find_user_by_uid(server_data, uid);

        // 2. Validar o pedido
        if (num_parsed < 8) { // Agora esperamos 8 argumentos no cabeçalho
            snprintf(response_msg, sizeof(response_msg), "RCE ERR\n");
        } else if (user == NULL || strcmp(user->password, password) != 0) {
            snprintf(response_msg, sizeof(response_msg), "RCE WRP\n");
        } else if (!user->is_logged_in) {
            snprintf(response_msg, sizeof(response_msg), "RCE NLG\n");
        } else {
            char full_date[17];
            snprintf(full_date, sizeof(full_date), "%s %s", date, time);

            // 3. Receber e guardar o ficheiro
            char event_dir[32];
            char event_filepath[64];
            snprintf(event_dir, sizeof(event_dir), "EVENTS/%03d", server_data->next_eid);
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
                // O cabeçalho tem 9 campos (contando com a hora), logo 8 espaços antes dos dados.
                int spaces_to_find = 9;
                while (spaces_to_find > 0 && (file_data_start = strchr(file_data_start, ' ')) != NULL) {
                    file_data_start++; // Avança para depois do espaço encontrado
                    spaces_to_find--;
                }

                if (file_data_start != NULL) {
                    long initial_data_len = bytes_read - (file_data_start - tcp_buffer);
                    fwrite(file_data_start, 1, initial_data_len, file);
                    long remaining_bytes = fsize - initial_data_len;
                    // Ler o resto do ficheiro do socket
                    while (remaining_bytes > 0) {
                        bytes_read = read(client_fd, tcp_buffer, sizeof(tcp_buffer));
                        if (bytes_read <= 0) break;
                        fwrite(tcp_buffer, 1, bytes_read, file);
                        remaining_bytes -= bytes_read;
                    }
                }
                fclose(file);

                // 4. Criar o evento e preparar a resposta
                Event* new_event = add_event(server_data, uid, name, full_date, attendance_size, fname);
                snprintf(response_msg, sizeof(response_msg), "RCE OK %03d\n", new_event->eid);
                if (verbose) printf("Evento %03d criado por %s.\n", new_event->eid, uid);
            }
        }
    } else if (strncmp(tcp_buffer, "LST", 3) == 0) {
        // --- Implementar list (LST/RLS) ---
        if (server_data->events == NULL) {
            if (verbose) printf("Nenhum evento para listar. A enviar RLS NOK.\n");
            snprintf(response_msg, sizeof(response_msg), "RLS NOK\n");
            if (verbose) {
                printf("Resposta TCP enviada para fd %d: %s", client_fd, response_msg);
            }
            write(client_fd, response_msg, strlen(response_msg));
        } else {
            // Enviar o cabeçalho da resposta
            snprintf(response_msg, sizeof(response_msg), "RLS OK ");
            write(client_fd, response_msg, strlen(response_msg));
            // Iterar sobre todos os eventos e enviar a informação de cada um
            Event* current = server_data->events;
            while (current != NULL) {
                // Formato: EID name state event_date
                // O enunciado do cliente pede para mostrar EID, nome e data. Vamos enviar tudo.
                snprintf(response_msg, sizeof(response_msg), "%03d %s %d %s\n",
                            current->eid, current->name, current->state, current->date);
                write(client_fd, response_msg, strlen(response_msg));
                current = current->next;
            }
            // Enviar um \n final para indicar o fim da lista, como especificado no enunciado.
            write(client_fd, "\n", 1);
            if (verbose) printf("Lista de eventos enviada para fd %d.\n", client_fd);
        }
        // A responsabilidade de fechar o socket é do loop principal em server.c
        return; // Retorna para não tentar enviar outra resposta no final
    } else {
        // Comando TCP desconhecido
        snprintf(response_msg, sizeof(response_msg), "ERR\n");
    }

    // Enviar resposta e fechar conexão
    ssize_t bytes_sent = write(client_fd, response_msg, strlen(response_msg));
    if (bytes_sent == -1) {
        perror("Erro ao escrever para o socket TCP do cliente");
    } else if (verbose) {
        printf("Resposta TCP enviada para fd %d: %s", client_fd, response_msg);
    }
}
