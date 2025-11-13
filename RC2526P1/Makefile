CC=gcc
CFLAGS=-Wall -g

all: user ES

user: user.c structures.h
	$(CC) $(CFLAGS) -o user user.c

ES: server.c structures.h
	$(CC) $(CFLAGS) -o ES server.c

clean:
	rm -f user ES
