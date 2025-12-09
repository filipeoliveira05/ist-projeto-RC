CC = gcc
CFLAGS = -Wall -g

# User
USER_SRCS = user.c user_commands.c utils.c
USER_OBJS = $(USER_SRCS:.c=.o)

# Servidor (ES)
ES_SRCS = server.c server_logic.c data_manager.c utils.c
ES_OBJS = $(ES_SRCS:.c=.o)

all: user ES

user: $(USER_OBJS)
	$(CC) $(CFLAGS) -o user $(USER_OBJS)

ES: $(ES_OBJS)
	$(CC) $(CFLAGS) -o ES $(ES_OBJS)

clean:
	rm -f user ES $(USER_OBJS) $(ES_OBJS)