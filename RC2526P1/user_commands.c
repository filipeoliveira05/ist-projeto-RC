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
    } else {
        printf("Não foi possível obter resposta do servidor.\n");
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
        printf("Não foi possível obter resposta do servidor.\n");
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
        printf("Não foi possível obter resposta do servidor.\n");
    }
    close(udp_fd);
}

void handle_create_command(ClientState *client_state, const char *name, const char *event_fname, const char *date, const char *time, const char *num_attendees) {
    if (!client_state->is_logged_in) {
        printf("Apenas utilizadores com sessão iniciada podem criar eventos.\n");
        return;
    }

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
    // Juntar a data e a hora numa única string para enviar ao servidor
    char full_date[17];
    snprintf(full_date, sizeof(full_date), "%s %s", date, time);
    int header_len = snprintf(request_header, sizeof(request_header), "CRE %s %s %s %s %s %s %ld ",
                              client_state->current_uid, client_state->current_password, name, full_date, num_attendees, event_fname, file_size);
    
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
    close(tcp_fd);
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
                char eid[6], name[12], date[17]; // Aumentar date para 17 para dd-mm-yyyy hh:mm
                if (sscanf(line, "%5s %11s %*s %16s", eid, name, date) == 3) { // %16s para a data completa
                    printf("%-5s | %-12s | %s\n", eid, name, date);
                }
                line = strtok(NULL, "\n");
            }
        } else {
            printf("Resposta inesperada do servidor: %s", response_buffer);
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
