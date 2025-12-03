// Define a fonte POSIX para ter acesso a getopt() e optarg no VS Code
#define _POSIX_C_SOURCE 200809L

#include "user_commands.h" // Inclui as funções de comando do utilizador
#include "structures.h"    // Continua a ser necessário para ClientState
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h> // Para gethostbyname

#define GROUP_NUMBER 66
#define DEFAULT_PORT (58000 + GROUP_NUMBER)

// --- Estado Global do Utilizador ---
// Guarda a informação do utilizador atualmente logado.
char current_uid[7] = {0};

int main(int argc, char *argv[]) {
    int opt;
    char *server_ip = "127.0.0.1"; // IP padrão é localhost
    int server_port = DEFAULT_PORT;

    // --- Parsing de Argumentos ---
    ClientState client_state;
    memset(&client_state, 0, sizeof(ClientState));
    client_state.is_logged_in = false;
    client_state.server_ip = server_ip; // Inicializa com o padrão
    client_state.server_port = server_port; // Inicializa com o padrão

    // Usamos getopt para processar os argumentos -n e -p
    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
        switch (opt) {
            case 'n':
                server_ip = optarg;
                break;
            case 'p':
                client_state.server_port = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Uso: %s [-n ESIP] [-p ESport]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    client_state.server_ip = server_ip; // Atualiza o IP após parsing

    printf("Aplicação de Utilizador a iniciar...\n");
    printf("A ligar ao Servidor de Eventos em %s:%d\n", client_state.server_ip, client_state.server_port);

    client_state.host_info = gethostbyname(client_state.server_ip);
    if (client_state.host_info == NULL) {
        fprintf(stderr, "ERRO, não foi possível encontrar o host '%s'\n", client_state.server_ip);
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
        char command[30], arg1[30], arg2[30], arg3[30], arg4[30], arg5[30];
        // O sscanf para de ler uma string no primeiro espaço. Para 'create', arg3 é a data, arg4 é a hora.
        int num_args = sscanf(command_buffer, "%s %s %s %s %s %s", command, arg1, arg2, arg3, arg4, arg5);

        if (num_args <= 0) { // Nenhum comando foi inserido (apenas Enter)
            continue;
        }

        if (strcmp(command, "login") == 0 && num_args == 3) {
            handle_login_command(&client_state, arg1, arg2);

        } else if (strcmp(command, "logout") == 0 && num_args == 1) {
            handle_logout_command(&client_state);

        } else if (strcmp(command, "unregister") == 0 && num_args == 1) {
            handle_unregister_command(&client_state);

        } else if (strcmp(command, "create") == 0 && num_args == 6) {
            // create <name> <event_fname> <date> <time> <num_attendees>
            handle_create_command(&client_state, arg1, arg2, arg3, arg4, arg5);

        } else if (strcmp(command, "list") == 0 && num_args == 1) {
            handle_list_command(&client_state);

        } else if (strcmp(command, "show") == 0 && num_args == 2) {
            handle_show_command(&client_state, arg1);

        } else if ((strcmp(command, "myevents") == 0 || strcmp(command, "mye") == 0) && num_args == 1) {
            handle_myevents_command(&client_state);

        } else if (strcmp(command, "close") == 0 && num_args == 2) {
            handle_close_command(&client_state, arg1);

        } else if (strcmp(command, "exit") == 0) {
            handle_exit_command(&client_state);
        } else {
            printf("Comando desconhecido ou número de argumentos inválido.\n");
        }
    }

}
