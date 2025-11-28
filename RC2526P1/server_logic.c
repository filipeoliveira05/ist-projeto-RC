#include "server_logic.h"
#include "data_manager.h" // Precisa do data_manager para manipular os dados
#include <stdio.h>
#include <stdlib.h> // Para atoi()
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h> // Para listar diretorias (comando list)

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
        if (strcmp(command, "LIN") == 0) {
            // Se a diretoria do user não existe, OU se existe mas não tem ficheiro de password (caso de re-registo)
            if (!user_exists(uid_str) || !user_password_file_exists(uid_str)) {
                create_user_files(uid_str, password_str);
                create_login_file(uid_str);
                snprintf(response_buffer, sizeof(response_buffer), "RLI REG\n");
                if (verbose) printf("Novo user %s registado e logado.\n", uid_str);
            } else { // O utilizador existe e tem um ficheiro de password, proceder com login normal
                if (check_user_password(uid_str, password_str)) {
                    create_login_file(uid_str);
                    snprintf(response_buffer, sizeof(response_buffer), "RLI OK\n");
                    if (verbose) printf("User %s logado com sucesso.\n", uid_str);
                } else {
                    snprintf(response_buffer, sizeof(response_buffer), "RLI NOK\n");
                    if (verbose) printf("Tentativa de login falhou para %s: password incorreta.\n", uid_str);
                }
            }
        } else if (strcmp(command, "LOU") == 0) {
            if (!user_exists(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RLO UNR\n");
            } else if (!check_user_password(uid_str, password_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RLO WRP\n");
            } else if (!is_user_logged_in(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RLO NOK\n");
            } else {
                remove_login_file(uid_str);
                snprintf(response_buffer, sizeof(response_buffer), "RLO OK\n");
                if (verbose) printf("User %s fez logout com sucesso.\n", uid_str);
            }
        } else if (strcmp(command, "UNR") == 0) {
            if (!user_exists(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RUR UNR\n");
            } else if (!check_user_password(uid_str, password_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RUR WRP\n");
            } else if (!is_user_logged_in(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RUR NOK\n");
            } else {
                remove_user_files(uid_str);
                snprintf(response_buffer, sizeof(response_buffer), "RUR OK\n");
                if (verbose) printf("User %s removido com sucesso.\n", uid_str);
            }
        } else {
            snprintf(response_buffer, sizeof(response_buffer), "RLI ERR\n");
            if (verbose) printf("Comando UDP desconhecido ou não implementado: %s\n", command);
        }
    } else {
        snprintf(response_buffer, sizeof(response_buffer), "RLI ERR\n");
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
        int header_len = 0; // Para guardar o tamanho do cabeçalho lido

        // 1. Analisar o cabeçalho de texto
        // O formato da data é "dd-mm-yyyy hh:mm". O sscanf com %s pára no espaço.
        // Temos de ler a data e a hora em separado.
        int num_parsed = sscanf(tcp_buffer, "CRE %6s %8s %10s %10s %5s %d %24s %ld %n",
                                uid, password, name, date, time, &attendance_size, fname, &fsize, &header_len);

        // 2. Validar o pedido
        if (num_parsed < 8) { // Agora esperamos 8 argumentos no cabeçalho
            snprintf(response_msg, sizeof(response_msg), "RCE ERR\n");
        } else if (!user_exists(uid) || !check_user_password(uid, password)) {
            snprintf(response_msg, sizeof(response_msg), "RCE WRP\n");
        } else if (!is_user_logged_in(uid)) {
            snprintf(response_msg, sizeof(response_msg), "RCE NLG\n");
        } else {
            char full_date[17];
            snprintf(full_date, sizeof(full_date), "%s %s", date, time);
            int current_eid = server_data->next_eid;
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
                // Usar o header_len obtido com %n para encontrar o início dos dados do ficheiro.
                if (header_len > 0 && header_len < bytes_read) {
                    long initial_data_len = bytes_read - header_len;
                    fwrite(tcp_buffer + header_len, 1, initial_data_len, file);
                    long remaining_bytes = fsize - initial_data_len;
                    while (remaining_bytes > 0) {
                        bytes_read = read(client_fd, tcp_buffer, sizeof(tcp_buffer));
                        if (bytes_read <= 0) break;
                        fwrite(tcp_buffer, 1, bytes_read, file);
                        remaining_bytes -= bytes_read;
                    }
                }
                fclose(file);

                // 4. Criar os ficheiros de metadados do evento
                char meta_path[256];
                // Criar subdiretorias
                snprintf(meta_path, sizeof(meta_path), "EVENTS/%03d/RESERVATIONS", current_eid);
                mkdir(meta_path, 0777);
                snprintf(meta_path, sizeof(meta_path), "EVENTS/%03d/DESCRIPTION", current_eid);
                rename(event_filepath, meta_path); // Move o ficheiro para a subdiretoria correta

                // Criar START_<eid>.txt
                snprintf(meta_path, sizeof(meta_path), "EVENTS/%03d/START_%03d.txt", current_eid, current_eid);
                FILE* start_file = fopen(meta_path, "w");
                if (start_file) {
                    fprintf(start_file, "%s %s %s %d %s\n", uid, name, fname, attendance_size, full_date);
                    fclose(start_file);
                }

                // Criar RES_<eid>.txt
                snprintf(meta_path, sizeof(meta_path), "EVENTS/%03d/RES_%03d.txt", current_eid, current_eid);
                FILE* res_file = fopen(meta_path, "w");
                if (res_file) {
                    fprintf(res_file, "0\n");
                    fclose(res_file);
                }

                // Criar ficheiro em USERS/<uid>/CREATED/
                snprintf(meta_path, sizeof(meta_path), "USERS/%s/CREATED/%03d.txt", uid, current_eid);
                FILE* created_file = fopen(meta_path, "w");
                if (created_file) fclose(created_file); // Ficheiro vazio

                // 5. Preparar resposta e incrementar EID
                snprintf(response_msg, sizeof(response_msg), "RCE OK %03d\n", current_eid);
                if (verbose) printf("Evento %03d criado por %s.\n", current_eid, uid);
                server_data->next_eid++;
            }
        }
    } else if (strncmp(tcp_buffer, "LST", 3) == 0) {
        // --- Implementar list (LST/RLS) ---
        DIR *d;
        struct dirent *dir;
        d = opendir("EVENTS");
        bool has_events = false;
        if (d) {
            // Enviar cabeçalho OK primeiro
            snprintf(response_msg, sizeof(response_msg), "RLS OK ");
            write(client_fd, response_msg, strlen(response_msg));

            while ((dir = readdir(d)) != NULL) {
                // Ignorar "." e ".."
                if (dir->d_name[0] == '.') continue;
                
                int eid = atoi(dir->d_name);
                if (eid > 0) { // Verifica se o nome da diretoria é um número válido
                    has_events = true;
                    char start_path[256];
                    // Usar o inteiro 'eid' com %03d em vez da string 'dir->d_name' com %s para eliminar o warning.
                    snprintf(start_path, sizeof(start_path), "EVENTS/%03d/START_%03d.txt", eid, eid);
                    
                    FILE* start_file = fopen(start_path, "r");
                    if (start_file) {
                        char owner_uid[7], event_name[11], desc_fname[25], event_date[17];
                        int total_seats;
                        // Formato no ficheiro: UID event_name desc_fname event_attend start_date start_time
                        if (fscanf(start_file, "%6s %10s %24s %d %16[^\n]", owner_uid, event_name, desc_fname, &total_seats, event_date) == 5) {
                            // TODO: Calcular o estado real do evento (ativo, passado, etc.)
                            int state = 1; // Por agora, assumir que todos estão ativos
                            snprintf(response_msg, sizeof(response_msg), "%03d %s %d %s\n", eid, event_name, state, event_date);
                            write(client_fd, response_msg, strlen(response_msg));
                        }
                        fclose(start_file);
                    }
                }
            }
            closedir(d);

            if (has_events) {
                write(client_fd, "\n", 1); // Terminador da lista
                if (verbose) printf("Lista de eventos enviada para fd %d.\n", client_fd);
            }
        }

        if (!has_events) { // Se o loop não encontrou nenhum evento
            if (verbose) printf("Nenhum evento para listar. A enviar RLS NOK.\n");
            snprintf(response_msg, sizeof(response_msg), "RLS NOK\n");
            if (verbose) {
                printf("Resposta TCP enviada para fd %d: %s", client_fd, response_msg);
            }
            write(client_fd, response_msg, strlen(response_msg));
        } else {
            // A resposta já foi enviada em pedaços
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
