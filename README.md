# Projeto Redes de Computadores 2025/2026 - Plataforma de Reserva de Eventos

## 1. Resumo do Projeto

Este projeto consiste na implementação de uma plataforma de reserva de eventos com uma arquitetura cliente-servidor, desenvolvida em C para um ambiente Linux. A plataforma é composta por duas aplicações principais:

- **Servidor de Eventos (ES)**: Um processo central que gere toda a lógica de negócio, incluindo o registo de utilizadores, criação e gestão de eventos, e processamento de reservas. O servidor é persistente, guardando todo o estado no sistema de ficheiros.
- **Aplicação de Utilizador (user)**: Uma interface no terminal que permite aos utilizadores interagir com o servidor para realizar ações como `login`, `create` (criar evento), `list` (listar eventos), `reserve` (reservar lugares), entre outras.

A comunicação entre o cliente e o servidor utiliza tanto o protocolo **UDP** como o **TCP**.

## 2. Compilação e Execução

O projeto inclui um `Makefile` para a compilação.

### Compilar

Para compilar ambos os executáveis (`ES` e `user`), execute o seguinte comando na raiz do projeto:

```bash
make
```

### Executar o Servidor (ES)

O servidor pode ser iniciado com as seguintes opções:

```bash
./ES [-p ESport] [-v]
```

- `-p ESport`: (Opcional) Especifica o porto no qual o servidor irá escutar. Por defeito, usa `58066`.
- `-v`: (Opcional) Ativa o modo "verbose", que imprime no terminal um log detalhado de todos os pedidos recebidos e ações executadas.

### Executar o Cliente (user)

A aplicação de utilizador pode ser iniciada com as seguintes opções:

```bash
./user [-n ESIP] [-p ESport]
```

- `-n ESIP`: (Opcional) Especifica o endereço IP do servidor. Por defeito, usa `127.0.0.1` (localhost).
- `-p ESport`: (Opcional) Especifica o porto do servidor. Por defeito, usa `58066`.

## 3. Organização do Código Fonte

O código está estruturado de forma modular para separar as diferentes responsabilidades da aplicação.

### Ficheiros Principais

- `server.c`: Ponto de entrada do Servidor de Eventos. Responsável pela inicialização dos sockets UDP e TCP, e pelo loop principal que utiliza `select()` para gerir a concorrência de múltiplos clientes e protocolos.
- `server_logic.c`: Contém a lógica de processamento para cada comando do protocolo (UDP e TCP). Atua como o "cérebro" do servidor, recebendo os pedidos brutos de `server.c` e orquestrando as ações necessárias.
- `data_manager.c`: Abstrai toda a interação com o sistema de ficheiros. Contém funções para criar, ler, atualizar e apagar dados de utilizadores e eventos, tratando o sistema de ficheiros como a base de dados da aplicação.
- `user.c`: Ponto de entrada da aplicação de Utilizador. Responsável pelo parsing de argumentos da linha de comandos e pelo loop principal que lê os comandos do utilizador.
- `user_commands.c`: Contém a implementação de cada comando do lado do cliente. Cada função prepara o pedido, comunica com o servidor (via UDP ou TCP) e formata a resposta para o utilizador.
- `utils.c`: Funções de utilidade partilhada tanto pelo servidor como pelo cliente. Inclui validações de formato (UID, password, data/hora) e outras operações comuns.
- `structures.h`: Define as estruturas de dados globais (`ServerState`, `ClientState`, `EventState`) utilizadas em toda a aplicação para manter o estado.
- `Makefile`: Automatiza o processo de compilação de ambos os executáveis.

## 4. Estratégias de Implementação e Decisões de Arquitetura

### 4.1. Arquitetura do Servidor

A decisão mais importante na arquitetura do servidor foi a utilização de um **`select()`**. Optámos desta forma de modo a evitar a complexidade associada a multi-threading ou multi-processing, como a necessidade de mutexes ou semáforos para proteger dados partilhados. O `select()` permite que um único processo monitorize o socket UDP, o socket de escuta TCP e todos os sockets de cliente TCP ativos, respondendo apenas quando há dados para ler. A concorrência é gerida de forma inerentemente segura. Como o servidor processa um pedido de cada vez no seu único thread, operações críticas como a leitura e incremento do ID do próximo evento (`next_eid`) tornam-se atómicas.

### 4.2. Persistência de Dados

Seguindo as diretrizes do enunciado, foi implementado um **mecanismo de persistência baseado no sistema de ficheiros**.

- **Estrutura**: Foram criadas as diretorias `USERS/` e `EVENTS/` para armazenar o estado. Esta abordagem permite uma gestão simples e visual do estado do servidor.
- **Atomicidade**: A escrita em ficheiros é inerentemente atómica para pequenas operações no Linux. Para operações mais complexas, como a criação de um evento, o servidor segue uma sequência de passos (criação de diretorias, escrita de ficheiros de metadados).

### 4.3. Protocolo de Comunicação

A implementação segue rigorosamente o protocolo especificado, utilizando UDP e TCP para os fins designados.

- **UDP**: Usado para interações rápidas e que não requerem garantia de entrega, como `login`, `logout`, `myevents` e `myreservations`.
- **TCP**: Usado para operações que necessitam de fiabilidade e envolvem a transferência de volumes de dados maiores ou sequências de comandos, como `create` (com upload de ficheiro), `show` (com download de ficheiro), `reserve` e `close`.

### 4.4. Robustez e Tratamento de Erros

Foi dada especial atenção à robustez, tanto no cliente como no servidor.

- **Validação no Servidor**: O servidor valida exaustivamente todos os parâmetros recebidos (formato de UID, password, datas, nomes, etc.), garantindo que dados malformados não corrompem o estado do sistema.
- **Leitura/Escrita em Sockets**: O código que lida com `read()` e `write()` em sockets TCP está preparado para lidar com escritas e leituras parciais, utilizando loops para garantir que todos os dados são enviados ou recebidos, conforme especificado nas notas de implementação do enunciado.
- **Tratamento de Respostas no Cliente**: O cliente foi programado para interpretar todas as possíveis respostas de sucesso e de erro do servidor, fornecendo feedback claro e útil ao utilizador.

## 5. Ficheiros Presentes

Conforme o enunciado, a submissão é um ficheiro `proj_66.zip` contendo:

- Todos os ficheiros de código fonte (`.c` e `.h`).
- O `Makefile` para compilação.
- Este ficheiro `readme.txt`.
- O ficheiro de auto-avaliação.
