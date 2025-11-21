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
#include <sys/stat.h> // Para stat()

#define GROUP_NUMBER 66
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

        // Aumentar buffers para acomodar todos os argumentos possíveis
        char command[30], arg1[30], arg2[30], arg3[30], arg4[30];
        // O sscanf para de ler uma string no primeiro espaço.
        int num_args = sscanf(command_buffer, "%s %s %s %s %s", command, arg1, arg2, arg3, arg4);

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

        } else if (strcmp(command, "create") == 0 && num_args == 5) {
            if (!is_logged_in) {
                printf("Apenas utilizadores com sessão iniciada podem criar eventos.\n");
                continue;
            }

            // --- Implementar create (TCP) ---
            // Comando: create <name> <event_fname> <event_date> <num_attendees>
            // Protocolo: CRE UID password name event_date attendance_size Fname Fsize Fdata
            char *name = arg1;
            char *event_fname = arg2;
            char *event_date = arg3;
            char *num_attendees = arg4;

            // 1. Verificar e ler o ficheiro local
            FILE *file = fopen(event_fname, "rb"); // Abrir em modo de leitura binária
            if (file == NULL) {
                perror("Erro ao abrir o ficheiro do evento");
                continue;
            }

            // 2. Obter o tamanho do ficheiro
            struct stat st;
            if (stat(event_fname, &st) != 0) {
                perror("Erro ao obter o tamanho do ficheiro");
                fclose(file);
                continue;
            }
            long file_size = st.st_size;

            // 3. Abrir conexão TCP
            int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (tcp_fd == -1) handle_error("Erro ao criar socket TCP");

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            memcpy((void*)&server_addr.sin_addr, host->h_addr_list[0], host->h_length);
            server_addr.sin_port = htons(server_port);

            if (connect(tcp_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
                handle_error("Erro ao conectar ao servidor TCP");
            }

            // 4. Formatar e enviar o pedido
            char request_header[512];
            int header_len = snprintf(request_header, sizeof(request_header), "CRE %s %s %s %s %s %s %ld ",
                                      current_uid, current_password, name, event_date, num_attendees, event_fname, file_size);
            
            // Enviar o cabeçalho de texto
            if (write(tcp_fd, request_header, header_len) == -1) {
                perror("Erro ao enviar cabeçalho TCP");
            } else {
                // Enviar os dados do ficheiro em blocos
                char file_buffer[1024];
                size_t bytes_read;
                while ((bytes_read = fread(file_buffer, 1, sizeof(file_buffer), file)) > 0) {
                    if (write(tcp_fd, file_buffer, bytes_read) == -1) {
                        perror("Erro ao enviar dados do ficheiro TCP");
                        break; // Sai do loop de escrita
                    }
                }
            }
            fclose(file);

            // 5. Ler a resposta do servidor
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

            // 6. Fechar a conexão
            close(tcp_fd);

        } else if (strcmp(command, "list") == 0 && num_args == 1) {
            // --- Implementar list (TCP) ---
            // Protocolo: LST -> RLS status [EID name state event_date]*

            // 1. Abrir conexão TCP
            int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
            if (tcp_fd == -1) handle_error("Erro ao criar socket TCP");

            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            memcpy((void*)&server_addr.sin_addr, host->h_addr_list[0], host->h_length);
            server_addr.sin_port = htons(server_port);

            if (connect(tcp_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
                handle_error("Erro ao conectar ao servidor TCP");
            }

            // 2. Enviar o pedido
            const char* request = "LST\n";
            if (write(tcp_fd, request, strlen(request)) == -1) {
                perror("Erro ao enviar pedido 'list'");
                close(tcp_fd);
                continue;
            }

            // 3. Ler a resposta
            // A resposta pode ser grande, então lemos em loop até o servidor fechar a conexão.
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

                    char *line = strtok(response_buffer + 7, "\n"); // Pula "RLS OK " e obtém a primeira linha
                    while (line != NULL) {
                        char eid[6], name[12], date[12]; // Removida a variável 'state'
                        // Usamos sscanf para extrair os campos de cada linha com limites de tamanho.
                        // O formato "%*s" ignora o campo 'state' (que é um número inteiro).
                        // EID (3 dígitos), name (máx 10 chars), date (dd-mm-yyyy, 10 chars).
                        if (sscanf(line, "%5s %11s %*s %11s", eid, name, date) == 3) {
                        printf("%-5s | %-12s | %s\n", eid, name, date);
                        }
                        // Pega a próxima linha
                        line = strtok(NULL, "\n");
                    }
                } else {
                    printf("Resposta inesperada do servidor: %s", response_buffer);
                }
            }

            // 4. Fechar a conexão
            close(tcp_fd);

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
