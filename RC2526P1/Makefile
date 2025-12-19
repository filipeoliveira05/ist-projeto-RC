CC = gcc
CFLAGS = -Wall -Wextra -Werror -g

DEPFLAGS = -MMD -MP

# User
USER_SRCS = user.c user_commands.c utils.c
USER_OBJS = $(USER_SRCS:.c=.o)
USER_DEPS = $(USER_SRCS:.c=.d)

# Servidor (ES)
ES_SRCS = server.c server_logic.c data_manager.c utils.c
ES_OBJS = $(ES_SRCS:.c=.o)
ES_DEPS = $(ES_SRCS:.c=.d)

all: user ES

user: $(USER_OBJS)
	$(CC) $(CFLAGS) -o user $(USER_OBJS)

ES: $(ES_OBJS)
	$(CC) $(CFLAGS) -o ES $(ES_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

.PHONY: all clean

clean:
	rm -f user ES $(USER_OBJS) $(ES_OBJS) $(USER_DEPS) $(ES_DEPS)

-include $(USER_DEPS) $(ES_DEPS)
