#include "user_commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> // Para gethostbyname
#include <sys/stat.h> // Para stat()
#include <errno.h> // Para errno
#include "utils.h" // Inclui a função is_valid_password

// Função de utilidade para tratamento de erros no cliente
void user_handle_error(const char *msg) {
    perror(msg);
    exit(1);
}

// Função auxiliar para criar e conectar um socket UDP
int create_udp_socket_and_connect(ClientState *client_state, struct sockaddr_in *server_addr_out) {
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd == -1) user_handle_error("Erro ao criar socket UDP");

    memset(server_addr_out, 0, sizeof(struct sockaddr_in));
    server_addr_out->sin_family = AF_INET;
    memcpy((void*)&server_addr_out->sin_addr, client_state->host_info->h_addr_list[0], client_state->host_info->h_length);
    server_addr_out->sin_port = htons(client_state->server_port);

    return udp_fd;
}

// Função auxiliar para criar e conectar um socket TCP
int create_tcp_socket_and_connect(ClientState *client_state, struct sockaddr_in *server_addr_out) {
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcp_fd == -1) user_handle_error("Erro ao criar socket TCP");

    memset(server_addr_out, 0, sizeof(struct sockaddr_in));
    server_addr_out->sin_family = AF_INET;
    memcpy((void*)&server_addr_out->sin_addr, client_state->host_info->h_addr_list[0], client_state->host_info->h_length);
    server_addr_out->sin_port = htons(client_state->server_port);

    if (connect(tcp_fd, (struct sockaddr*)server_addr_out, sizeof(struct sockaddr_in)) == -1) {
        user_handle_error("Erro ao conectar ao servidor TCP");
    }
    return tcp_fd;
}

void handle_login_command(ClientState *client_state, const char *uid, const char *password) {
    if (client_state->is_logged_in) {
        printf("Já existe um utilizador com sessão iniciada. Por favor, faça logout primeiro.\n");
        return;
    }
    if (!is_valid_uid(uid)) {
        printf("Erro: O UID deve ter exatamente 6 dígitos.\n");
        return;
    }
    if (!is_valid_password(password)) {
        printf("Erro: A password deve ter exatamente 8 caracteres alfanuméricos.\n");
        return;
    }
    struct sockaddr_in server_addr;
    int udp_fd = create_udp_socket_and_connect(client_state, &server_addr);

    char request_buffer[128];
    char response_buffer[128];

    snprintf(request_buffer, sizeof(request_buffer), "LIN %s %s\n", uid, password);
    sendto(udp_fd, request_buffer, strlen(request_buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    socklen_t addr_len = sizeof(server_addr);
    ssize_t n = recvfrom(udp_fd, response_buffer, sizeof(response_buffer) - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
    
    if (n > 0) {
        response_buffer[n] = '\0';
        if (strncmp(response_buffer, "RLI OK", 6) == 0) {
            printf("Login bem-sucedido.\n");
            client_state->is_logged_in = true;
            strncpy(client_state->current_uid, uid, sizeof(client_state->current_uid) - 1);
            client_state->current_uid[sizeof(client_state->current_uid) - 1] = '\0';
            strncpy(client_state->current_password, password, sizeof(client_state->current_password) - 1);
            client_state->current_password[sizeof(client_state->current_password) - 1] = '\0';
        } else if (strncmp(response_buffer, "RLI REG", 7) == 0) {
            printf("Novo utilizador registado com sucesso.\n");
            client_state->is_logged_in = true;
            strncpy(client_state->current_uid, uid, sizeof(client_state->current_uid) - 1);
            client_state->current_uid[sizeof(client_state->current_uid) - 1] = '\0';
            strncpy(client_state->current_password, password, sizeof(client_state->current_password) - 1);
            client_state->current_password[sizeof(client_state->current_password) - 1] = '\0';
        } else if (strncmp(response_buffer, "RLI NOK", 7) == 0) {
            printf("Login falhou: password incorreta ou utilizador não existe.\n");
        } else {
            printf("Resposta inesperada do servidor: %s", response_buffer);
        }
    } else { // n <= 0
        if (n == 0) {
            printf("Servidor não respondeu (conexão UDP pode ter sido perdida).\n");
        } else {
            perror("Erro ao receber resposta do servidor");
        }
    }
    close(udp_fd);
}

void handle_logout_command(ClientState *client_state) {
    if (!client_state->is_logged_in) {
        printf("Não há sessão iniciada.\n");
        return;
    }

    struct sockaddr_in server_addr;
    int udp_fd = create_udp_socket_and_connect(client_state, &server_addr);

    char request_buffer[128];
    char response_buffer[128];

    snprintf(request_buffer, sizeof(request_buffer), "LOU %s %s\n", client_state->current_uid, client_state->current_password);
    sendto(udp_fd, request_buffer, strlen(request_buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    socklen_t addr_len = sizeof(server_addr);
    ssize_t n = recvfrom(udp_fd, response_buffer, sizeof(response_buffer) - 1, 0, (struct sockaddr*)&server_addr, &addr_len);

    if (n > 0) {
        response_buffer[n] = '\0';
        if (strncmp(response_buffer, "RLO OK", 6) == 0) {
            printf("Logout bem-sucedido.\n");
            client_state->is_logged_in = false;
            memset(client_state->current_uid, 0, sizeof(client_state->current_uid));
            memset(client_state->current_password, 0, sizeof(client_state->current_password));
        } else {
            printf("Logout falhou. Resposta do servidor: %s", response_buffer);
        }
    } else {
        if (n == 0) {
            printf("Servidor não respondeu (conexão UDP pode ter sido perdida).\n");
        } else {
            perror("Erro ao receber resposta do servidor");
        }
    }
    close(udp_fd);
}

void handle_unregister_command(ClientState *client_state) {
    if (!client_state->is_logged_in) {
        printf("Não há sessão iniciada para anular o registo.\n");
        return;
    }

    struct sockaddr_in server_addr;
    int udp_fd = create_udp_socket_and_connect(client_state, &server_addr);

    char request_buffer[128], response_buffer[128];
    snprintf(request_buffer, sizeof(request_buffer), "UNR %s %s\n", client_state->current_uid, client_state->current_password);
    sendto(udp_fd, request_buffer, strlen(request_buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    socklen_t addr_len = sizeof(server_addr);
    ssize_t n = recvfrom(udp_fd, response_buffer, sizeof(response_buffer) - 1, 0, (struct sockaddr*)&server_addr, &addr_len);
    if (n > 0) {
        response_buffer[n] = '\0';
        if (strncmp(response_buffer, "RUR OK", 6) == 0) {
            printf("Registo anulado com sucesso.\n");
            client_state->is_logged_in = false;
            memset(client_state->current_uid, 0, sizeof(client_state->current_uid));
            memset(client_state->current_password, 0, sizeof(client_state->current_password));
        } else {
            printf("Anulação de registo falhou. Resposta do servidor: %s", response_buffer);
        }
    } else {
        if (n == 0) {
            printf("Servidor não respondeu (conexão UDP pode ter sido perdida).\n");
        } else {
            perror("Erro ao receber resposta do servidor");
        }
    }
    close(udp_fd);
}

void handle_create_command(ClientState *client_state, const char *name, const char *event_fname, const char *date, const char *time, const char *num_attendees) {
    if (!client_state->is_logged_in) {
        printf("Apenas utilizadores com sessão iniciada podem criar eventos.\n");
        return;
    }

    if (!is_valid_event_name(name)) {
        printf("Erro: O nome do evento deve ter no máximo 10 caracteres alfanuméricos.\n");
        return;
    }

    if (!is_valid_event_filename(event_fname)) {
        printf("Erro: O nome do ficheiro de descrição deve ter no máximo 24 caracteres e conter apenas alfanuméricos, '-', '_' ou '.'.\n");
        return;
    }

    char full_datetime[17]; // dd-mm-yyyy hh:mm + '\0'
    snprintf(full_datetime, sizeof(full_datetime), "%s %s", date, time);
    if (!is_valid_datetime_format(full_datetime)) {
        printf("Erro: Data e hora inválida ou formato incorreto (dd-mm-yyyy hh:mm).\n");
        return;
    }

    if (!is_valid_number_attendees(num_attendees)) {
        printf("Erro: O número de lugares deve ser um valor numérico entre 10 e 999.\n");
        return;
    }

    // Truncar o nome do evento para o máximo de 10 caracteres, conforme protocolo
    char truncated_name[11]; // 10 caracteres + '\0'
    strncpy(truncated_name, name, sizeof(truncated_name) - 1);
    truncated_name[sizeof(truncated_name) - 1] = '\0'; // Garantir terminação nula


    FILE *file = fopen(event_fname, "rb");
    if (file == NULL) {
        perror("Erro ao abrir o ficheiro do evento");
        return;
    }

    struct stat st;
    if (stat(event_fname, &st) != 0) {
        perror("Erro ao obter o tamanho do ficheiro");
        fclose(file);
        return;
    }
    long file_size = st.st_size;

    struct sockaddr_in server_addr;
    int tcp_fd = create_tcp_socket_and_connect(client_state, &server_addr);

    char request_header[512];
    // Ordem correta dos argumentos, correspondendo ao sscanf do servidor (num_attendees como int):
    // CRE <uid> <password> <truncated_name> <date> <time> <attendance_size_int> <fname> <fsize>
    int header_len = snprintf(request_header, sizeof(request_header), "CRE %s %s %s %s %s %d %s %ld ",
                              client_state->current_uid, client_state->current_password, truncated_name, date, time, atoi(num_attendees), event_fname, file_size);
    
    if (write(tcp_fd, request_header, header_len) == -1) {
        perror("Erro ao enviar cabeçalho TCP");
    } else {
        char file_buffer[1024];
        size_t bytes_read;
        while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
            if (write(tcp_fd, file_buffer, bytes_read) == -1) {
                perror("Erro ao enviar dados do ficheiro TCP");
                break;
            }
        }
    }
    fclose(file);

    // Sinalizar ao servidor que terminámos de enviar dados.
    // Isto é crucial para evitar deadlocks quando o servidor está à espera de mais dados do ficheiro.
    shutdown(tcp_fd, SHUT_WR);

    char response_buffer[128];
    ssize_t n = read(tcp_fd, response_buffer, sizeof(response_buffer) - 1);
    if (n > 0) {
        response_buffer[n] = '\0';
        char status[4], eid_str[4];
        if (sscanf(response_buffer, "RCE %s %s", status, eid_str) == 2 && strcmp(status, "OK") == 0) {
            printf("Evento criado com sucesso com o ID: %s\n", eid_str);
        } else {
            printf("Não foi possível criar o evento. Resposta do servidor: %s", response_buffer);
        }
    }
    if (n == 0) {
        printf("Servidor fechou a conexão inesperadamente.\n");
    } else if (n < 0) {
        perror("Erro de comunicação com o servidor");
    }
    close(tcp_fd); // Fechar o socket TCP
}

void handle_list_command(ClientState *client_state) {
    struct sockaddr_in server_addr;
    int tcp_fd = create_tcp_socket_and_connect(client_state, &server_addr);

    const char* request = "LST\n";
    if (write(tcp_fd, request, strlen(request)) == -1) {
        perror("Erro ao enviar pedido 'list'");
        close(tcp_fd);
        return;
    }

    char response_buffer[4096];
    ssize_t total_bytes_read = 0;
    ssize_t bytes_read;
    while ((bytes_read = read(tcp_fd, response_buffer + total_bytes_read, sizeof(response_buffer) - total_bytes_read - 1)) > 0) {
        total_bytes_read += bytes_read;
    }

    if (total_bytes_read > 0) {
        response_buffer[total_bytes_read] = '\0';

        if (strncmp(response_buffer, "RLS NOK", 7) == 0) {
            printf("Nenhum evento disponível de momento.\n");
        } else if (strncmp(response_buffer, "RLS OK", 6) == 0) {
            printf("Eventos disponíveis:\n");
            printf("%-5s | %-12s | %s\n", "EID", "Nome", "Data");
            printf("------|--------------|----------------\n");

            char *line = strtok(response_buffer + 7, "\n");
            while (line != NULL) {
                char eid[4], name[11], date[17]; // EID: 3 digitos + '\0'; Name: 10 chars + '\0'; Date: 16 chars + '\0'
                int state; // O estado é um inteiro
                if (sscanf(line, "%3s %10s %d %16[^\n]", eid, name, &state, date) == 4) {
                    printf("%-5s | %-12s | %s\n", eid, name, date);
                }
                line = strtok(NULL, "\n");
            }
        } else {
            printf("Resposta inesperada do servidor: %s", response_buffer);
        } // else if (total_bytes_read <= 0)
    } else if (total_bytes_read == 0) {
        printf("Servidor não enviou dados ou fechou a conexão.\n");
    } else { // total_bytes_read < 0
        perror("Erro de comunicação com o servidor");
    }
    close(tcp_fd);
}

void handle_show_command(ClientState *client_state, const char *eid) {
    struct sockaddr_in server_addr;
    int tcp_fd = create_tcp_socket_and_connect(client_state, &server_addr);

    char request[16];
    snprintf(request, sizeof(request), "SED %s\n", eid);
    if (write(tcp_fd, request, strlen(request)) == -1) {
        perror("Erro ao enviar pedido 'show'");
        close(tcp_fd);
        return;
    }

    char response_buffer[4096];
    ssize_t bytes_read = read(tcp_fd, response_buffer, sizeof(response_buffer) - 1);
    if (bytes_read <= 0) {
        printf("Servidor não respondeu ou fechou a conexão.\n");
        close(tcp_fd);
        return;
    }
    response_buffer[bytes_read] = '\0';

    if (strncmp(response_buffer, "RSE NOK", 7) == 0) {
        printf("Evento não encontrado.\n");
    } else if (strncmp(response_buffer, "RSE OK", 6) == 0) {
        char owner_uid[7], name[11], date[11], time[6], fname[25];
        int total_seats, reserved_seats;
        long fsize;
        int header_len = 0;

        int num_parsed = sscanf(response_buffer, "RSE OK %6s %10s %10s %5s %d %d %24s %ld %n",
                                owner_uid, name, date, time, &total_seats, &reserved_seats, fname, &fsize, &header_len);

        if (num_parsed < 8) {
            printf("Erro: Resposta do servidor mal formatada.\n");
        } else {
            printf("Detalhes do Evento %s:\n", eid);
            printf("  - Nome: %s\n", name);
            printf("  - Data: %s %s\n", date, time);
            printf("  - Criador: %s\n", owner_uid);
            printf("  - Lugares: %d / %d\n", reserved_seats, total_seats);
            printf("  - Ficheiro de Descrição: %s (%ld bytes)\n", fname, fsize);

            FILE *file = fopen(fname, "wb");
            if (file == NULL) {
                perror("Erro ao criar ficheiro local");
            } else {
                // Escrever a porção do ficheiro que já foi lida no buffer
                long initial_data_len = bytes_read - header_len;
                if (initial_data_len > 0) {
                    fwrite(response_buffer + header_len, 1, initial_data_len, file);
                }

                // Ler o resto do ficheiro do socket
                long remaining_bytes = fsize - initial_data_len;
                while (remaining_bytes > 0) {
                    bytes_read = read(tcp_fd, response_buffer, sizeof(response_buffer));
                    if (bytes_read <= 0) break; // Conexão fechada ou erro
                    fwrite(response_buffer, 1, bytes_read, file);
                    remaining_bytes -= bytes_read;
                }
                fclose(file);
                printf("Ficheiro '%s' guardado com sucesso.\n", fname);
            }
        }
    } else {
        printf("Resposta inesperada do servidor: %s", response_buffer);
    }

    close(tcp_fd);
}

void handle_myevents_command(ClientState *client_state) {
    if (!client_state->is_logged_in) {
        printf("Apenas utilizadores com sessão iniciada podem listar os seus eventos.\n");
        return;
    }

    struct sockaddr_in server_addr;
    int udp_fd = create_udp_socket_and_connect(client_state, &server_addr);

    char request_buffer[128];
    char response_buffer[4096];

    snprintf(request_buffer, sizeof(request_buffer), "LME %s %s\n", client_state->current_uid, client_state->current_password);
    sendto(udp_fd, request_buffer, strlen(request_buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    socklen_t addr_len = sizeof(server_addr);
    ssize_t n = recvfrom(udp_fd, response_buffer, sizeof(response_buffer) - 1, 0, (struct sockaddr*)&server_addr, &addr_len);

    if (n > 0) {
        response_buffer[n] = '\0';
        if (strncmp(response_buffer, "RME OK", 6) == 0) {
            printf("Eventos criados por si:\n");
            printf("%-5s | %s\n", "EID", "Estado");
            printf("------|------------------\n");

            char *token_ptr = response_buffer + 7; // Aponta para depois de "RME OK "
            char *token;
            while ((token = strtok_r(token_ptr, " \n", &token_ptr))) {
                char *eid = token;
                token = strtok_r(NULL, " \n", &token_ptr);
                if (!token) break; // Evita erro se a lista terminar de forma ímpar
                int state_code = atoi(token);
                const char* state_str;
                switch(state_code) {
                    case 0: state_str = "Passado"; break;
                    case 1: state_str = "Ativo"; break;
                    case 2: state_str = "Esgotado"; break;
                    case 3: state_str = "Fechado"; break;
                    default: state_str = "Desconhecido"; break;
                }
                printf("%-5s | %s\n", eid, state_str);
            }
        } else if (strncmp(response_buffer, "RME NOK", 7) == 0) {
            printf("Não criou nenhum evento.\n");
        } else if (strncmp(response_buffer, "RME NLG", 7) == 0) {
            printf("Erro: A sua sessão parece ter expirado. Por favor, faça login novamente.\n");
        } else if (strncmp(response_buffer, "RME WRP", 7) == 0) {
            printf("Erro: Password incorreta.\n");
        } else {
            printf("Resposta inesperada do servidor: %s", response_buffer);
        }
    } else {
        if (n == 0) {
            printf("Servidor não respondeu (conexão UDP pode ter sido perdida).\n");
        } else {
            perror("Erro ao receber resposta do servidor");
        }
    }

    close(udp_fd);
}

void handle_close_command(ClientState *client_state, const char *eid) {
    if (!client_state->is_logged_in) {
        printf("Apenas utilizadores com sessão iniciada podem fechar eventos.\n");
        return;
    }

    struct sockaddr_in server_addr;
    int tcp_fd = create_tcp_socket_and_connect(client_state, &server_addr);

    char request[128];
    snprintf(request, sizeof(request), "CLS %s %s %s\n", client_state->current_uid, client_state->current_password, eid);
    if (write(tcp_fd, request, strlen(request)) == -1) {
        perror("Erro ao enviar pedido 'close'");
        close(tcp_fd);
        return;
    }

    char response_buffer[128];
    ssize_t n = read(tcp_fd, response_buffer, sizeof(response_buffer) - 1);
    if (n <= 0) {
        printf("Servidor não respondeu ou fechou a conexão.\n");
    } else {
        response_buffer[n] = '\0';
        if (strncmp(response_buffer, "RCL OK", 6) == 0) {
            printf("Evento %s fechado com sucesso.\n", eid);
        } else if (strncmp(response_buffer, "RCL NOK", 7) == 0) {
            printf("Erro ao fechar evento %s: Utilizador não existe ou password incorreta.\n", eid);
        } else if (strncmp(response_buffer, "RCL NLG", 7) == 0) {
            printf("Erro ao fechar evento %s: Utilizador não está logado.\n", eid);
        } else if (strncmp(response_buffer, "RCL NOE", 7) == 0) {
            printf("Erro ao fechar evento %s: Evento não existe.\n", eid);
        } else if (strncmp(response_buffer, "RCL EOW", 7) == 0) {
            printf("Erro ao fechar evento %s: Não é o proprietário do evento.\n", eid);
        } else if (strncmp(response_buffer, "RCL SLD", 7) == 0) {
            printf("Erro ao fechar evento %s: Evento já esgotado.\n", eid);
        } else if (strncmp(response_buffer, "RCL PST", 7) == 0) {
            printf("Erro ao fechar evento %s: Evento já passou.\n", eid);
        } else if (strncmp(response_buffer, "RCL CLO", 7) == 0) {
            printf("Erro ao fechar evento %s: Evento já está fechado.\n", eid);
        } else {
            printf("Resposta inesperada do servidor: %s", response_buffer);
        }
    }
    close(tcp_fd);
}

void handle_reserve_command(ClientState *client_state, const char *eid, const char *num_seats_str) {
    if (!client_state->is_logged_in) {
        printf("Apenas utilizadores com sessão iniciada podem fazer reservas.\n");
        return;
    }

    int num_seats = atoi(num_seats_str);
    if (num_seats <= 0) {
        printf("Número de lugares inválido.\n");
        return;
    }

    struct sockaddr_in server_addr;
    int tcp_fd = create_tcp_socket_and_connect(client_state, &server_addr);

    char request[128];
    snprintf(request, sizeof(request), "RID %s %s %s %d\n", client_state->current_uid, client_state->current_password, eid, num_seats);
    if (write(tcp_fd, request, strlen(request)) == -1) {
        perror("Erro ao enviar pedido 'reserve'");
        close(tcp_fd);
        return;
    }

    char response_buffer[128];
    ssize_t n = read(tcp_fd, response_buffer, sizeof(response_buffer) - 1);
    if (n <= 0) {
        printf("Servidor não respondeu ou fechou a conexão.\n");
    } else {
        response_buffer[n] = '\0';
        if (strncmp(response_buffer, "RRI ACC", 7) == 0) {
            printf("Reserva para %d lugares no evento %s efetuada com sucesso.\n", num_seats, eid);
        } else if (strncmp(response_buffer, "RRI REJ", 7) == 0) {
            int available_seats;
            if (sscanf(response_buffer, "RRI REJ %d", &available_seats) == 1) {
                printf("Reserva rejeitada. Apenas existem %d lugares disponíveis.\n", available_seats);
            } else {
                printf("Reserva rejeitada por falta de lugares.\n");
            }
        } else if (strncmp(response_buffer, "RRI CLS", 7) == 0) {
            printf("Reserva falhou: o evento %s já se encontra fechado.\n", eid);
        } else if (strncmp(response_buffer, "RRI SLD", 7) == 0) {
            printf("Reserva falhou: o evento %s está esgotado.\n", eid);
        } else if (strncmp(response_buffer, "RRI PST", 7) == 0) {
            printf("Reserva falhou: a data do evento %s já passou.\n", eid);
        } else if (strncmp(response_buffer, "RRI NOK", 7) == 0) {
            printf("Reserva falhou: o evento %s não existe ou não está ativo.\n", eid);
        } else if (strncmp(response_buffer, "RRI WRP", 7) == 0) {
            printf("Reserva falhou: password incorreta.\n");
        } else {
            printf("Reserva falhou. Resposta do servidor: %s", response_buffer);
        }
    }
    close(tcp_fd);
}

void handle_myreservations_command(ClientState *client_state) {
    if (!client_state->is_logged_in) {
        printf("Apenas utilizadores com sessão iniciada podem listar as suas reservas.\n");
        return;
    }

    struct sockaddr_in server_addr;
    int udp_fd = create_udp_socket_and_connect(client_state, &server_addr);

    char request_buffer[128];
    char response_buffer[8192]; // Buffer maior para acomodar até 50 reservas

    snprintf(request_buffer, sizeof(request_buffer), "LMR %s %s\n", client_state->current_uid, client_state->current_password);
    sendto(udp_fd, request_buffer, strlen(request_buffer), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    socklen_t addr_len = sizeof(server_addr);
    ssize_t n = recvfrom(udp_fd, response_buffer, sizeof(response_buffer) - 1, 0, (struct sockaddr*)&server_addr, &addr_len);

    if (n > 0) {
        response_buffer[n] = '\0';
        if (strncmp(response_buffer, "RMR OK", 6) == 0) {
            printf("As suas reservas:\n");
            printf("%-5s | %-20s | %s\n", "EID", "Data da Reserva", "Lugares");
            printf("------|----------------------|--------\n");

            char *token_ptr = response_buffer + 7; // Aponta para depois de "RMR OK "
            char *eid, *date, *time, *value;
            while ((eid = strtok_r(token_ptr, " ", &token_ptr)) != NULL) {
                date = strtok_r(NULL, " ", &token_ptr);
                time = strtok_r(NULL, " ", &token_ptr);
                value = strtok_r(NULL, " \n", &token_ptr);

                if (!date || !time || !value) break;

                printf("%-5s | %s %-9s | %s\n", eid, date, time, value);
            }
        } else if (strncmp(response_buffer, "RMR NOK", 7) == 0) {
            printf("Não efetuou nenhuma reserva.\n");
        } else if (strncmp(response_buffer, "RMR NLG", 7) == 0) {
            printf("Erro: A sua sessão parece ter expirado. Por favor, faça login novamente.\n");
        } else if (strncmp(response_buffer, "RMR WRP", 7) == 0) {
            printf("Erro: Password incorreta.\n");
        } else {
            printf("Resposta inesperada do servidor: %s", response_buffer);
        }
    } else {
        printf("Não foi possível obter resposta do servidor.\n");
    }

    close(udp_fd);
}

void handle_change_password_command(ClientState *client_state, const char *old_password, const char *new_password) {
    if (!client_state->is_logged_in) {
        printf("Apenas utilizadores com sessão iniciada podem alterar a password.\n");
        return;
    }

    if (!is_valid_password(old_password) || !is_valid_password(new_password)) {
        printf("Erro: As passwords devem ter exatamente 8 caracteres alfanuméricos.\n");
        return;
    }
    struct sockaddr_in server_addr;
    int tcp_fd = create_tcp_socket_and_connect(client_state, &server_addr);

    char request[128];
    snprintf(request, sizeof(request), "CPS %s %s %s\n", client_state->current_uid, old_password, new_password);
    if (write(tcp_fd, request, strlen(request)) == -1) {
        perror("Erro ao enviar pedido 'changePass'");
        close(tcp_fd);
        return;
    }

    char response_buffer[128];
    ssize_t n = read(tcp_fd, response_buffer, sizeof(response_buffer) - 1);
    if (n <= 0) {
        printf("Servidor não respondeu ou fechou a conexão.\n");
    } else {
        response_buffer[n] = '\0';
        if (strncmp(response_buffer, "RCP OK", 6) == 0) {
            printf("Password alterada com sucesso.\n");
            // Atualizar a password no estado do cliente
            strncpy(client_state->current_password, new_password, sizeof(client_state->current_password) - 1);
            client_state->current_password[sizeof(client_state->current_password) - 1] = '\0';
        } else if (strncmp(response_buffer, "RCP NLG", 7) == 0) {
            printf("Erro: Utilizador não está logado.\n");
        } else if (strncmp(response_buffer, "RCP NOK", 7) == 0) {
            printf("Erro: Password antiga incorreta.\n");
        } else if (strncmp(response_buffer, "RCP NID", 7) == 0) {
            printf("Erro: Utilizador não existe.\n");
        } else {
            printf("Erro: Resposta inesperada do servidor: %s", response_buffer);
        }
    }
    close(tcp_fd);
}

void handle_exit_command(ClientState *client_state) {
    if (client_state->is_logged_in) {
        printf("Utilizador ainda com sessão iniciada. Por favor, execute o comando 'logout' primeiro.\n");
    } else {
        printf("A terminar a aplicação.\n");
        exit(0); // Termina o programa
    }
}
