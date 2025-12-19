#include "server_logic.h"
#include "data_manager.h" // Precisa do data_manager para manipular os dados
#include <stdio.h>
#include <stdlib.h> // Para atoi()
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h> // Para listar diretorias (comando list)
#include <time.h>
#include "utils.h" // Inclui a função is_valid_password

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
        // Remove a quebra de linha do buffer para um log mais limpo
        buffer[strcspn(buffer, "\n")] = 0;
        printf("VERBOSE: Received UDP request from %s:%d -> [%s]\n", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), buffer);
    }

    // Analisar apenas o comando primeiro para um tratamento de erros mais robusto
    if (sscanf(buffer, "%3s", command) == 1) {
        if (strcmp(command, "LIN") == 0) {
            if (sscanf(buffer, "%*s %6s %8s", uid_str, password_str) != 2) {
                snprintf(response_buffer, sizeof(response_buffer), "RLI ERR\n");
                if (verbose) printf("Verbose: LIN failed. Reason: Invalid syntax (missing arguments).\n");
            } else if (!is_valid_uid(uid_str)) { // Validação do UID
                snprintf(response_buffer, sizeof(response_buffer), "RLI ERR\n");
                if (verbose) printf("Verbose: LIN failed. Reason: Invalid UID format for '%s'.\n", uid_str);
            }
            else if (!is_valid_password(password_str)) { // Validação da password
                snprintf(response_buffer, sizeof(response_buffer), "RLI ERR\n");
                if (verbose) printf("Verbose: LIN failed for %s. Reason: Invalid password format.\n", uid_str);
            }
            // Se a diretoria do user não existe, OU se existe mas não tem ficheiro de password (caso de re-registo)
            else if (!user_exists(uid_str) || !user_password_file_exists(uid_str)) {
                create_user_files(uid_str, password_str);
                create_login_file(uid_str);
                snprintf(response_buffer, sizeof(response_buffer), "RLI REG\n");
                if (verbose) printf("Verbose: New user %s registered and logged in. Files created.\n", uid_str);
            } else { // O utilizador existe e tem um ficheiro de password, proceder com login normal
                if (check_user_password(uid_str, password_str)) {
                    create_login_file(uid_str);
                    snprintf(response_buffer, sizeof(response_buffer), "RLI OK\n");
                    if (verbose) printf("Verbose: User %s logged in successfully.\n", uid_str);
                } else {
                    snprintf(response_buffer, sizeof(response_buffer), "RLI NOK\n");
                    if (verbose) printf("Verbose: LIN failed for %s. Reason: Incorrect password.\n", uid_str);
                }
            }
        } else if (strcmp(command, "LOU") == 0) {
            if (sscanf(buffer, "%*s %6s %8s", uid_str, password_str) != 2) {
                // Se não conseguir fazer parse do UID/pass, o user não está logado.
                snprintf(response_buffer, sizeof(response_buffer), "RLO NOK\n");
                if (verbose) printf("Verbose: LOU failed. Reason: Request from a non-logged-in client.\n");
            } else if (!is_valid_uid(uid_str)) { // Validação do UID
                snprintf(response_buffer, sizeof(response_buffer), "RLO ERR\n");
                if (verbose) printf("Verbose: LOU failed. Reason: Invalid UID format for '%s'.\n", uid_str);
            } else if (!user_exists(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RLO UNR\n");
                if (verbose) printf("Verbose: LOU failed for %s. Reason: User not registered.\n", uid_str);
            } else if (!check_user_password(uid_str, password_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RLO WRP\n");
                if (verbose) printf("Verbose: LOU failed for %s. Reason: Incorrect password.\n", uid_str);
            } else if (!is_user_logged_in(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RLO NOK\n");
                if (verbose) printf("Verbose: LOU failed for %s. Reason: User not logged in.\n", uid_str);
            } else {
                remove_login_file(uid_str);
                snprintf(response_buffer, sizeof(response_buffer), "RLO OK\n");
                if (verbose) printf("Verbose: User %s logged out successfully. Login file removed.\n", uid_str);
            }
        } else if (strcmp(command, "UNR") == 0) {
            if (sscanf(buffer, "%*s %6s %8s", uid_str, password_str) != 2) {
                snprintf(response_buffer, sizeof(response_buffer), "RUR NOK\n");
                if (verbose) printf("Verbose: UNR failed. Reason: Request from a non-logged-in client.\n");
            } else if (!is_valid_uid(uid_str)) { // Validação do UID
                snprintf(response_buffer, sizeof(response_buffer), "RUR ERR\n");
                if (verbose) printf("Verbose: UNR failed. Reason: Invalid UID format for '%s'.\n", uid_str);
            } else if (!user_exists(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RUR UNR\n");
                if (verbose) printf("Verbose: UNR failed for %s. Reason: User not registered.\n", uid_str);
            } else if (!check_user_password(uid_str, password_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RUR WRP\n");
                if (verbose) printf("Verbose: UNR failed for %s. Reason: Incorrect password.\n", uid_str);
            } else if (!is_user_logged_in(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RUR NOK\n");
                if (verbose) printf("Verbose: UNR failed for %s. Reason: User not logged in.\n", uid_str);
            } else {
                remove_user_files(uid_str);
                snprintf(response_buffer, sizeof(response_buffer), "RUR OK\n");
                if (verbose) printf("Verbose: User %s unregistered successfully. User files removed.\n", uid_str);
            }
        } else if (strcmp(command, "LME") == 0) {
            if (sscanf(buffer, "%*s %6s %8s", uid_str, password_str) != 2) {
                snprintf(response_buffer, sizeof(response_buffer), "RME NLG\n");
                if (verbose) printf("Verbose: LME failed. Reason: Request from a non-logged-in client.\n");
            } else if (!is_valid_uid(uid_str)) { // Validação do UID
                snprintf(response_buffer, sizeof(response_buffer), "RME ERR\n");
                if (verbose) printf("Verbose: LME failed. Reason: Invalid UID format for '%s'.\n", uid_str);
            } else if (!user_exists(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RME UNR\n"); // Embora não especificado, é um bom status
                if (verbose) printf("Verbose: LME failed for %s. Reason: User not registered.\n", uid_str);
            } else if (!check_user_password(uid_str, password_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RME WRP\n");
                if (verbose) printf("Verbose: LME failed for %s. Reason: Incorrect password.\n", uid_str);
            } else if (!is_user_logged_in(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RME NLG\n");
                if (verbose) printf("Verbose: LME failed for %s. Reason: User not logged in.\n", uid_str);
            } else {
                char created_dir_path[64];
                snprintf(created_dir_path, sizeof(created_dir_path), "USERS/%s/CREATED", uid_str);

                struct dirent **namelist;
                int n = scandir(created_dir_path, &namelist, NULL, alphasort);

                if (n <= 2) { // Apenas "." e ".."
                    snprintf(response_buffer, sizeof(response_buffer), "RME NOK\n");
                    if (verbose) printf("Verbose: User %s has not created any events.\n", uid_str);
                    if (n > 0) {
                        for(int i=0; i<n; i++) free(namelist[i]);
                        free(namelist);
                    }
                } else {
                    char temp_response[4096] = "RME OK";
                    for (int i = 0; i < n; i++) {
                        if (namelist[i]->d_name[0] == '.') {
                            free(namelist[i]);
                            continue;
                        }
                        
                        char eid_str[4];
                        strncpy(eid_str, namelist[i]->d_name, 3);
                        eid_str[3] = '\0';

                        int state = get_event_state(eid_str);

                        char event_info[10];
                        snprintf(event_info, sizeof(event_info), " %s %d", eid_str, state);
                        strcat(temp_response, event_info);

                        free(namelist[i]);
                    }
                    free(namelist);
                    strcat(temp_response, "\n");
                    strcpy(response_buffer, temp_response);
                    if (verbose) printf("Verbose: Sent list of created events for user %s.\n", uid_str);
                }
            }
        } else if (strcmp(command, "LMR") == 0) {
            if (sscanf(buffer, "%*s %6s %8s", uid_str, password_str) != 2) {
                snprintf(response_buffer, sizeof(response_buffer), "RMR NLG\n");
                if (verbose) printf("Verbose: LMR failed. Reason: Request from a non-logged-in client.\n");
            } else if (!is_valid_uid(uid_str)) { // Validação do UID
                snprintf(response_buffer, sizeof(response_buffer), "RMR ERR\n");
                if (verbose) printf("Verbose: LMR failed. Reason: Invalid UID format for '%s'.\n", uid_str);
            } else if (!user_exists(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RMR UNR\n");
                if (verbose) printf("Verbose: LMR failed for %s. Reason: User not registered.\n", uid_str);
            } else if (!check_user_password(uid_str, password_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RMR WRP\n");
                if (verbose) printf("Verbose: LMR failed for %s. Reason: Incorrect password.\n", uid_str);
            } else if (!is_user_logged_in(uid_str)) {
                snprintf(response_buffer, sizeof(response_buffer), "RMR NLG\n");
                if (verbose) printf("Verbose: LMR failed for %s. Reason: User not logged in.\n", uid_str);
            } else {
                char reserved_dir_path[64];
                snprintf(reserved_dir_path, sizeof(reserved_dir_path), "USERS/%s/RESERVED", uid_str);

                struct dirent **namelist;
                // Usar scandir com alphasort para ordenar os ficheiros. Como o nome começa com YYYYMMDD, a ordem será cronológica.
                int n = scandir(reserved_dir_path, &namelist, NULL, alphasort);

                if (n <= 2) { // Apenas "." e ".."
                    snprintf(response_buffer, sizeof(response_buffer), "RMR NOK\n");
                    if (verbose) printf("Verbose: User %s has no reservations.\n", uid_str);
                    if (n > 0) {
                        for(int i=0; i<n; i++) free(namelist[i]);
                        free(namelist);
                    }
                } else {
                    char temp_response[8192] = "RMR OK";
                    int reservations_count = 0;
                    // Iterar de trás para a frente para obter os mais recentes, até ao limite de 50
                    for (int i = n - 1; i >= 0 && reservations_count < 50; i--) {
                        if (namelist[i]->d_name[0] == '.') {
                            free(namelist[i]);
                            continue;
                        }

                        char reservation_filepath[512]; // Aumentado para evitar warning de truncagem
                        snprintf(reservation_filepath, sizeof(reservation_filepath), "%s/%s", reserved_dir_path, namelist[i]->d_name);
                        FILE *res_file = fopen(reservation_filepath, "r");
                        if (res_file) {
                            char eid_str[4], res_uid[7], res_date[11], res_time[9];
                            int num_seats;
                            // Ler do conteúdo do ficheiro: EID UID SEATS DATE TIME
                            if (fscanf(res_file, "%3s %6s %d %10s %8s", eid_str, res_uid, &num_seats, res_date, res_time) == 5) {
                                char res_info[50];
                                snprintf(res_info, sizeof(res_info), " %s %s %s %d", eid_str, res_date, res_time, num_seats);
                                strcat(temp_response, res_info);
                                reservations_count++;
                            }
                            fclose(res_file);
                        }
                        free(namelist[i]);
                    }
                    free(namelist);
                    strcat(temp_response, "\n");
                    strcpy(response_buffer, temp_response);
                    if (verbose) printf("Verbose: Sent list of reservations for user %s.\n", uid_str);
                }
            }
        } else {
            snprintf(response_buffer, sizeof(response_buffer), "ERR\n"); // Resposta genérica de erro para comando desconhecido
            if (verbose) printf("Verbose: Unknown or unimplemented UDP command: '%s'.\n", command);
        }
    } else {
        snprintf(response_buffer, sizeof(response_buffer), "ERR\n"); // Resposta genérica de erro de sintaxe
        if (verbose) printf("Verbose: UDP request syntax error. Could not parse command.\n");
    }
    
    ssize_t sent_bytes = sendto(udp_fd, response_buffer, strlen(response_buffer), 0,
                                (struct sockaddr*)client_addr, client_len);
    if (sent_bytes == -1) {
        perror("Erro ao enviar resposta UDP");
    } else if (verbose) {
        printf("VERBOSE: UDP response sent to %s:%d: %s", inet_ntoa(client_addr->sin_addr), ntohs(client_addr->sin_port), response_buffer);
    }
}

void process_tcp_request(int client_fd, char *tcp_buffer, ssize_t bytes_read, ServerState *server_data, bool verbose, char *response_buffer, int response_size) {
    // ... cole aqui toda a lógica de processamento TCP ...
    // (if/else para CRE, LST, etc.)
    // ... e a lógica de write() da resposta.
    // NOTA: Esta função não deve fechar o socket, isso é responsabilidade do loop principal em server.c


    // Log do tipo de pedido TCP, conforme o enunciado, se o modo verbose estiver ativo.
    if (verbose) {
        char command_type[4];
        // Tenta ler os 3 primeiros caracteres como o tipo de comando.
        if (sscanf(tcp_buffer, "%3s", command_type) == 1) {
            // Criar uma cópia do buffer para o log para não modificar o original
            char log_buffer[256];
            strncpy(log_buffer, tcp_buffer, sizeof(log_buffer) - 1);
            log_buffer[sizeof(log_buffer) - 1] = '\0';

            // Remover a quebra de linha da cópia para um log mais limpo
            log_buffer[strcspn(log_buffer, "\n")] = '\0';
            printf("VERBOSE: Received TCP request from fd %d -> [%s] \"%s\"\n", client_fd, command_type, log_buffer);
        }
    }

    // --- Implementar create (CRE/RCE) ---
    if (strncmp(tcp_buffer, "CRE", 3) == 0) {
        char uid[7], password[9], name[11], date[11], time[6], fname[25];
        char num_attendees_str[5]; // Ler como string primeiro para validação
        long fsize; 
        int header_len = 0; // Para guardar o tamanho do cabeçalho lido
        
        // 1. Validar primeiro as credenciais. Se falhar, é porque o utilizador não está logado.
        if (sscanf(tcp_buffer, "CRE %6s %8s", uid, password) != 2 || !is_user_logged_in(uid)) { // A verificação de login aqui é redundante se o cliente não envia UID, mas mantemos por segurança
            snprintf(response_buffer, response_size, "RCE NLG\n");
            if (verbose) printf("Verbose: CRE failed. Reason: User not logged in.\n");
        } else {
            // Copiar a parte do cabeçalho para um buffer temporário para evitar corromper tcp_buffer com sscanf
            char header_buffer[512];
            strncpy(header_buffer, tcp_buffer, sizeof(header_buffer) - 1);
            header_buffer[sizeof(header_buffer) - 1] = '\0';
            // 2. Se as credenciais são válidas, analisar o resto do cabeçalho
            int num_parsed = sscanf(header_buffer, "CRE %*s %*s %10s %10s %5s %4s %24s %ld %n",
                                    name, date, time, num_attendees_str, fname, &fsize, &header_len);

            if (num_parsed < 6) { 
                snprintf(response_buffer, response_size, "RCE ERR\n");
                if (verbose) printf("Verbose: CRE failed. Reason: Invalid request syntax (missing arguments).\n");
            } else if (!check_user_password(uid, password)) { // Validação da password
            snprintf(response_buffer, response_size, "RCE ERR\n");
                if (verbose) printf("Verbose: CRE failed for %s. Reason: Incorrect password.\n", uid);
            } else {
                char full_date[17];
                snprintf(full_date, sizeof(full_date), "%s %s", date, time);

                // Validações dos parâmetros movidas do cliente para o servidor
                if (!is_valid_event_name(name) || !is_valid_event_filename(fname) || !is_valid_datetime_format(full_date) || !is_valid_number_attendees(num_attendees_str)) {
                    snprintf(response_buffer, response_size, "RCE NOK\n");
                    if (verbose) printf("Verbose: CRE failed. Reason: Invalid parameter values (name, filename, date, or attendees).\n");
                } else {
                    int current_eid = server_data->next_eid;
                    // 3. Receber e guardar o ficheiro
                    int attendance_size = atoi(num_attendees_str);
                    char event_dir_path[32];
                    char description_dir_path[64];
                    char event_filepath[128];

                    snprintf(event_dir_path, sizeof(event_dir_path), "EVENTS/%03d", current_eid);
                    mkdir("EVENTS", 0700); // Cria o diretório principal se não existir
                    mkdir(event_dir_path, 0700); // Cria o diretório específico do evento
                    
                    snprintf(description_dir_path, sizeof(description_dir_path), "%s/DESCRIPTION", event_dir_path);
                    mkdir(description_dir_path, 0700); // Cria a subdiretoria DESCRIPTION

                    snprintf(event_filepath, sizeof(event_filepath), "%s/%s", description_dir_path, fname);
                    FILE *file = fopen(event_filepath, "wb");
                    if (file == NULL) {
                        perror("Erro ao criar ficheiro do evento no servidor");
                        snprintf(response_buffer, response_size, "RCE NOK\n");
                        if (verbose) printf("Verbose: CRE failed for %s. Reason: Server failed to create event file.\n", uid);
                    } else {
                        // Usar o header_len obtido com %n para encontrar o início dos dados do ficheiro.
                        if (header_len > 0) {
                            long initial_data_len = bytes_read - header_len;
                            fwrite(tcp_buffer + header_len, 1, initial_data_len, file);
                            long remaining_bytes = fsize - initial_data_len; // Corrigir o cálculo dos bytes restantes
                            while (remaining_bytes > 0) {
                                memset(tcp_buffer, 0, 1024); // Limpar o buffer antes de ler, usando o tamanho real
                                bytes_read = read(client_fd, tcp_buffer, 1024);
                                if (bytes_read <= 0) break;
                                fwrite(tcp_buffer, 1, bytes_read, file);
                                remaining_bytes -= bytes_read;
                            }
                        }
                        fclose(file);
                        if (verbose) printf("Verbose: Event %03d description file '%s' received and saved.\n", current_eid, fname);

                        // 4. Criar os ficheiros de metadados do evento
                        char meta_path[256];
                        // Criar subdiretoria de reservas
                        snprintf(meta_path, sizeof(meta_path), "EVENTS/%03d/RESERVATIONS", current_eid);
                        mkdir(meta_path, 0700);

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
                        snprintf(response_buffer, response_size, "RCE OK %03d\n", current_eid);
                        if (verbose) printf("Verbose: Event %03d created successfully by user %s.\n", current_eid, uid);
                        server_data->next_eid++;

                        // Guardar o novo next_eid no ficheiro para persistência
                        char eid_file_path[64];
                        snprintf(eid_file_path, sizeof(eid_file_path), "EVENTS/eid.dat");
                        FILE *eid_file = fopen(eid_file_path, "w");
                        if (eid_file != NULL) {
                            fprintf(eid_file, "%d", server_data->next_eid);
                            fclose(eid_file);
                            if (verbose) printf("Verbose: Persisted next_eid: %d.\n", server_data->next_eid);
                        } else {
                            perror("Erro ao guardar next_eid em EVENTS/eid.dat");
                        }
                    }
                }
            }
        }
        if (verbose) printf("VERBOSE CRE: TCP response prepared for fd %d: %s", client_fd, response_buffer);
        return; // Comando CRE processado, retornar
    } else if (strncmp(tcp_buffer, "LST", 3) == 0) {
        // --- Implementar list (LST/RLS) ---
        struct dirent **namelist;
        int n;

        // Usar scandir para obter uma lista ordenada de entradas na diretoria EVENTS
        n = scandir("EVENTS", &namelist, NULL, alphasort);
        if (n < 0) {
            perror("scandir");
            snprintf(response_buffer, response_size, "RLS NOK\n");
            if (verbose) printf("VERBOSE LST: TCP response prepared for fd %d: RLS NOK\n", client_fd);
            return;
        }

        char full_response[8192] = "RLS OK"; // Buffer para construir a resposta completa
        bool found_any_event = false;

        for (int i = 0; i < n; i++) {
            if (namelist[i]->d_name[0] == '.') {
                free(namelist[i]);
                continue;
            }

            int eid = atoi(namelist[i]->d_name);
            if (eid > 0) {
                char start_path[256];
                snprintf(start_path, sizeof(start_path), "EVENTS/%03d/START_%03d.txt", eid, eid);
                
                FILE* start_file = fopen(start_path, "r");
                if (start_file) {
                    found_any_event = true;
                    char owner_uid[7], event_name[11], desc_fname[25], event_date_str[11], event_time_str[6];
                    int total_seats;
                    if (fscanf(start_file, "%6s %10s %24s %d %10s %5s", owner_uid, event_name, desc_fname, &total_seats, event_date_str, event_time_str) == 6) {
                        char current_eid_str[12];
                        snprintf(current_eid_str, sizeof(current_eid_str), "%03d", eid);
                        char full_event_date[17];
                        snprintf(full_event_date, sizeof(full_event_date), "%s %s", event_date_str, event_time_str);
                        int state = get_event_state(current_eid_str);
                        
                        char temp_event_line[128];
                        snprintf(temp_event_line, sizeof(temp_event_line), " %03d %s %d %s", eid, event_name, state, full_event_date);
                        strcat(full_response, temp_event_line);
                    }
                    fclose(start_file);
                }
            }
            free(namelist[i]);
        }

        if (!found_any_event) {
            snprintf(response_buffer, response_size, "RLS NOK\n");
            if (verbose) printf("Verbose: LST failed. Reason: No events found to list.\n");
            if (verbose) printf("VERBOSE LST: TCP response sent to fd %d: RLS NOK\n", client_fd);
        } else {
            strcat(full_response, "\n");
            strncpy(response_buffer, full_response, response_size - 1);
            if (verbose) {
                full_response[strcspn(full_response, "\n")] = 0; // Remover o \n para o log
                printf("VERBOSE LST: TCP response sent to fd %d: %s\n", client_fd, full_response);
            }
        }

        free(namelist); // Libertar o array de ponteiros
        return; // Retorna para não tentar enviar outra resposta no final
    } else if (strncmp(tcp_buffer, "CLS", 3) == 0) {
        char uid[7], password[9], eid_str[4];

        if (sscanf(tcp_buffer, "CLS %6s %8s", uid, password) != 2 || !is_user_logged_in(uid)) {
            snprintf(response_buffer, response_size, "RCL NLG\n");
            if (verbose) printf("Verbose: CLS failed. Reason: User not logged.\n");
        } else {
            if (sscanf(tcp_buffer, "CLS %*s %*s %3s", eid_str) != 1) {
                snprintf(response_buffer, response_size, "RCL ERR\n");
                if (verbose) printf("Verbose: CLS failed. Reason: Invalid request syntax (missing EID).\n");
            } else if (!check_user_password(uid, password)) {
                snprintf(response_buffer, response_size, "RCL NOK\n");
                if (verbose) printf("Verbose: CLS failed for %s. Reason: Incorrect password.\n", uid);
            } else {
                char event_dir_path[32];
                snprintf(event_dir_path, sizeof(event_dir_path), "EVENTS/%s", eid_str);

                struct stat st;
                if (stat(event_dir_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
                    snprintf(response_buffer, response_size, "RCL NOE\n");
                    if (verbose) printf("Verbose: CLS failed for EID %s. Reason: Event does not exist.\n", eid_str);
                } else {
                    // Verificar se o utilizador é o proprietário do evento
                    char start_path[64];
                    snprintf(start_path, sizeof(start_path), "%s/START_%s.txt", event_dir_path, eid_str);
                    FILE *start_file = fopen(start_path, "r");
                    if (!start_file) {
                        snprintf(response_buffer, response_size, "RCL NOE\n"); // START file missing, treat as non-existent
                        if (verbose) printf("Verbose: CLS failed for EID %s. Reason: Event doesn't exist or data is corrupted (missing START file).\n", eid_str);
                    } else {
                        char owner_uid[7];
                        // Ler apenas o UID do proprietário do ficheiro START
                        if (fscanf(start_file, "%6s", owner_uid) != 1) {
                            snprintf(response_buffer, response_size, "RCL NOE\n"); // Ficheiro START mal formatado
                            if (verbose) printf("Verbose: CLS failed for EID %s. Reason: Event doesn't exist or data is corrupted (malformed START file).\n", eid_str);
                            fclose(start_file);
                        } else {
                            fclose(start_file);
                            if (strcmp(owner_uid, uid) != 0) {
                                snprintf(response_buffer, response_size, "RCL EOW\n");
                                if (verbose) printf("Verbose: CLS failed for EID %s. Reason: User %s is not the owner.\n", eid_str, uid);
                            } else {
                                // O utilizador é o proprietário, agora verificar o estado do evento
                                EventState state = get_event_state(eid_str);

                                switch (state) {
                                    case CLOSED:
                                        snprintf(response_buffer, response_size, "RCL CLO\n");
                                        if (verbose) printf("Verbose: CLS failed for EID %s. Reason: Event already closed.\n", eid_str);
                                        break;
                                    case PAST:
                                        snprintf(response_buffer, response_size, "RCL PST\n");
                                        // Conforme o guia, se o evento já passou, o servidor deve criar o ficheiro END_
                                        create_end_file(eid_str);
                                        if (verbose) printf("Verbose: CLS failed for EID %s. Reason: Event already in the past.\n", eid_str);
                                        break;
                                    case SOLD_OUT:
                                        snprintf(response_buffer, response_size, "RCL SLD\n");
                                        if (verbose) printf("Verbose: CLS failed for EID %s. Reason: Event is sold out.\n", eid_str);
                                        break;
                                    case ACTIVE:
                                        // Evento ativo e o proprietário quer fechar
                                        create_end_file(eid_str); // Criar o ficheiro END_
                                        snprintf(response_buffer, response_size, "RCL OK\n");
                                        if (verbose) printf("Verbose: Event %s closed successfully by owner %s.\n", eid_str, uid);
                                        break;
                                    default:
                                        snprintf(response_buffer, response_size, "RCL ERR\n"); // Estado inesperado
                                        if (verbose) printf("Verbose: CLS failed for EID %s. Reason: Unknown event state.\n", eid_str);
                                        break;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (verbose) printf("VERBOSE CLS: TCP response prepared for fd %d: %s", client_fd, response_buffer);
        return; // Comando CLS processado, retornar
    } else if (strncmp(tcp_buffer, "RID", 3) == 0) {
        char uid[7], password[9], eid_str[4];
        int seats_to_reserve;

        if (sscanf(tcp_buffer, "RID %6s %8s", uid, password) != 2 || !is_user_logged_in(uid)) {
            snprintf(response_buffer, response_size, "RRI NLG\n");
            if (verbose) printf("Verbose: RID failed. Reason: User not logged in.\n");
        } else {
            if (sscanf(tcp_buffer, "RID %*s %*s %3s %d", eid_str, &seats_to_reserve) != 2) {
                snprintf(response_buffer, response_size, "RRI ERR\n");
                if (verbose) printf("Verbose: RID failed. Reason: Invalid request syntax (missing arguments).\n");
            } else if (!check_user_password(uid, password)) {
                snprintf(response_buffer, response_size, "RRI WRP\n");
                if (verbose) printf("Verbose: RID failed for %s. Reason: Incorrect password.\n", uid);
            } else {
                char event_dir_path[32];
                snprintf(event_dir_path, sizeof(event_dir_path), "EVENTS/%s", eid_str);

                struct stat st;
                if (stat(event_dir_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
                    snprintf(response_buffer, response_size, "RRI NOK\n"); // Evento não existe
                    if (verbose) printf("Verbose: RID failed for EID %s. Reason: Event isn't active or doesn't exist.\n", eid_str);
                } else {
                    EventState state = get_event_state(eid_str);
                    switch (state) {
                        case CLOSED:
                            snprintf(response_buffer, response_size, "RRI CLS\n");
                            if (verbose) printf("Verbose: RID failed for EID %s. Reason: Event is closed.\n", eid_str);
                            break;
                        case PAST:
                            snprintf(response_buffer, response_size, "RRI PST\n");
                            if (verbose) printf("Verbose: RID failed for EID %s. Reason: Event is in the past.\n", eid_str);
                            break;
                        case SOLD_OUT:
                            snprintf(response_buffer, response_size, "RRI SLD\n");
                            if (verbose) printf("Verbose: RID failed for EID %s. Reason: Event is sold out.\n", eid_str);
                            break;
                        case ACTIVE: {
                            // Ler total de lugares e lugares reservados
                            char start_path[64], res_path[64];
                            snprintf(start_path, sizeof(start_path), "%s/START_%s.txt", event_dir_path, eid_str);
                            snprintf(res_path, sizeof(res_path), "%s/RES_%s.txt", event_dir_path, eid_str);

                            FILE *start_file = fopen(start_path, "r");
                            FILE *res_file = fopen(res_path, "r");

                            if (!start_file || !res_file) {
                                snprintf(response_buffer, response_size, "RRI ERR\n"); // Ficheiros internos corrompidos
                                if (verbose) printf("Verbose: RID failed for EID %s. Reason: Server data corruption (missing START/RES file).\n", eid_str);
                            } else {
                                int total_seats, reserved_seats;
                                fscanf(start_file, "%*s %*s %*s %d", &total_seats);
                                fscanf(res_file, "%d", &reserved_seats);
                                fclose(start_file);
                                fclose(res_file);

                                int available_seats = total_seats - reserved_seats;
                                if (seats_to_reserve > available_seats) {
                                    snprintf(response_buffer, response_size, "RRI REJ %d\n", available_seats);
                                    if (verbose) printf("Verbose: RID rejected for EID %s. Reason: Not enough seats (requested %d, available %d).\n", eid_str, seats_to_reserve, available_seats);
                                } else {
                                    // Atualizar o ficheiro de total de reservas
                                    res_file = fopen(res_path, "w");
                                    fprintf(res_file, "%d\n", reserved_seats + seats_to_reserve);
                                    fclose(res_file);

                                    // Criar os ficheiros de registo da reserva
                                    char date_str[11], time_str[7], datetime_str[20];
                                    get_datetime_for_filename(date_str, time_str, sizeof(date_str));
                                    time_t now = time(NULL);
                                    strftime(datetime_str, sizeof(datetime_str), "%d-%m-%Y %H:%M:%S", localtime(&now));

                                    char reservation_filename[128];
                                    snprintf(reservation_filename, sizeof(reservation_filename), "R-%s-%s_%s.txt", uid, date_str, time_str);

                                    char event_res_path[256], user_res_path[256];
                                    snprintf(event_res_path, sizeof(event_res_path), "%s/RESERVATIONS/%s", event_dir_path, reservation_filename);
                                    snprintf(user_res_path, sizeof(user_res_path), "USERS/%s/RESERVED/%s", uid, reservation_filename);

                                    FILE *event_res_file = fopen(event_res_path, "w");
                                    FILE *user_res_file = fopen(user_res_path, "w");

                                    if (event_res_file && user_res_file) {
                                        fprintf(event_res_file, "%s %s %d %s\n", eid_str, uid, seats_to_reserve, datetime_str);
                                        fprintf(user_res_file, "%s %s %d %s\n", eid_str, uid, seats_to_reserve, datetime_str); // O conteúdo é o mesmo
                                        snprintf(response_buffer, response_size, "RRI ACC\n");
                                        if (verbose) printf("Verbose: Reservation for %d seats on event %s by user %s accepted.\n", seats_to_reserve, eid_str, uid);
                                    } else {
                                        // Erro ao criar ficheiros de registo, reverter a contagem
                                        snprintf(response_buffer, response_size, "RRI ERR\n"); // Erro ao criar ficheiros de reserva
                                        if (verbose) printf("Verbose: RID failed for EID %s. Reason: Server failed to create reservation files.\n", eid_str);
                                        FILE* revert_res_file = fopen(res_path, "w");
                                        if (revert_res_file) {
                                            fprintf(revert_res_file, "%d\n", reserved_seats);
                                            fclose(revert_res_file);
                                        }
                                    }
                                    if (event_res_file) fclose(event_res_file);
                                    if (user_res_file) fclose(user_res_file);
                                }
                            }
                            break;
                        }
                        default:
                            snprintf(response_buffer, response_size, "RRI ERR\n");
                            if (verbose) printf("Verbose: RID failed for EID %s. Reason: Unknown event state.\n", eid_str);
                            break;
                    }
                }
            }
        }
        // Enviar resposta para RID
        if (verbose) printf("VERBOSE RID: TCP response prepared for fd %d: %s", client_fd, response_buffer);
        return; // Comando RID processado, retornar
    } else if (strncmp(tcp_buffer, "CPS", 3) == 0) {
        char uid[7], old_password[9], new_password[9];

        if (sscanf(tcp_buffer, "CPS %6s", uid) != 1 || !is_user_logged_in(uid)) {
            snprintf(response_buffer, response_size, "RCP NLG\n");
            if (verbose) printf("Verbose: CPS failed. Reason: User not logged in.\n");
        } else {
            if (sscanf(tcp_buffer, "CPS %*s %8s %8s", old_password, new_password) != 2) {
                snprintf(response_buffer, response_size, "RCP ERR\n");
                if (verbose) printf("Verbose: CPS failed. Reason: Invalid request syntax (missing passwords).\n");
            } else if (!is_valid_password(old_password) || !is_valid_password(new_password)) {
                snprintf(response_buffer, response_size, "RCP ERR\n");
                if (verbose) printf("Verbose: CPS failed for %s. Reason: Invalid password format.\n", uid);
            } else if (!check_user_password(uid, old_password)) {
                snprintf(response_buffer, response_size, "RCP NOK\n");
                if (verbose) printf("Verbose: CPS failed for %s. Reason: Incorrect old password.\n", uid);
            } else {
                // Todas as validações passaram, alterar a password
                if (update_user_password(uid, new_password)) {
                    snprintf(response_buffer, response_size, "RCP OK\n");
                    if (verbose) printf("Verbose: Password for user %s changed successfully.\n", uid);
                } else {
                    snprintf(response_buffer, response_size, "RCP ERR\n"); // Erro interno ao escrever no ficheiro
                    if (verbose) printf("Verbose: CPS failed for %s. Reason: Server failed to write new password file.\n", uid);
                }
            }
        }
        // Enviar resposta para CPS
        if (verbose) printf("VERBOSE CPS: TCP response prepared for fd %d: %s", client_fd, response_buffer);
        return; // Comando CPS processado, retornar
    } else if (strncmp(tcp_buffer, "SED", 3) == 0) {
        char eid_str[4];
        if (sscanf(tcp_buffer, "SED %3s", eid_str) == 1) {
            char event_dir_path[32];
            snprintf(event_dir_path, sizeof(event_dir_path), "EVENTS/%s", eid_str);
            
            struct stat st;
            if (stat(event_dir_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
                snprintf(response_buffer, response_size, "RSE NOK\n");
                if (verbose) printf("Verbose: SED failed for EID %s. Reason: Event does not exist.\n", eid_str);
                if (verbose) printf("VERBOSE SED: TCP response sent to fd %d: RSE NOK\n", client_fd);
            } else {
                char start_path[64], res_path[64];
                snprintf(start_path, sizeof(start_path), "%s/START_%s.txt", event_dir_path, eid_str);
                snprintf(res_path, sizeof(res_path), "%s/RES_%s.txt", event_dir_path, eid_str);
                
                FILE *start_file = fopen(start_path, "r");
                FILE *res_file = fopen(res_path, "r");

                if (!start_file || !res_file) {
                    snprintf(response_buffer, response_size, "RSE NOK\n");
                    if (verbose) printf("Verbose: SED failed for EID %s. Reason: Server data corruption (missing START/RES file).\n", eid_str);
                    if (start_file) fclose(start_file);
                    if (res_file) fclose(res_file);
                } else {
                    char owner_uid[7], name[11], fname[25], date[11], time[6];
                    int total_seats, reserved_seats = 0;

                    fscanf(start_file, "%6s %10s %24s %d %10s %5s", owner_uid, name, fname, &total_seats, date, time);
                    fscanf(res_file, "%d", &reserved_seats);
                    fclose(start_file);
                    fclose(res_file);

                    char desc_file_path[128];
                    snprintf(desc_file_path, sizeof(desc_file_path), "%s/DESCRIPTION/%s", event_dir_path, fname);

                    if (stat(desc_file_path, &st) != 0) { // Check if description file exists
                        snprintf(response_buffer, response_size, "RSE NOK\n");
                        if (verbose) printf("Verbose: SED failed for EID %s. Reason: Description file is missing.\n", eid_str);
                    } else {
                        long fsize = st.st_size;
                        char full_date[17];
                        snprintf(full_date, sizeof(full_date), "%s %s", date, time);

                        // Preparar o cabeçalho da resposta
                        snprintf(response_buffer, response_size, "RSE OK %s %s %s %d %d %s %ld ",
                                 owner_uid, name, full_date, total_seats, reserved_seats, fname, fsize);
                        if (verbose) {
                            printf("VERBOSE SED: TCP response header prepared for fd %d: %s\n", client_fd, response_buffer);
                        }
                        ssize_t header_bytes_sent = write(client_fd, response_buffer, strlen(response_buffer));
                        
                        if (header_bytes_sent > 0) {
                            // Enviar o conteúdo do ficheiro apenas se o cabeçalho foi enviado com sucesso
                            FILE *desc_file = fopen(desc_file_path, "rb");
                            if (desc_file) {
                                char file_buffer[1024];
                                size_t bytes_read_from_file;
                                while ((bytes_read_from_file = fread(file_buffer, 1, sizeof(file_buffer), desc_file)) > 0) {
                                    if (write(client_fd, file_buffer, bytes_read_from_file) == -1) {
                                        break; // Stop sending if there's a write error
                                    }
                                }
                                fclose(desc_file);
                            }
                        }
                        return; // Retorna para não enviar a resposta padrão no final
                    }
                }
            }
        } else {
            snprintf(response_buffer, response_size, "RSE ERR\n");
            if (verbose) printf("VERBOSE SED: TCP response sent to fd %d: RSE ERR\n", client_fd);
        }
        return;
    } else {
        // Comando TCP desconhecido
        snprintf(response_buffer, response_size, "ERR\n");
        if (verbose) printf("Verbose: Unknown TCP command received.\n");
        return; // Terminar após tratar o erro
    }
}
