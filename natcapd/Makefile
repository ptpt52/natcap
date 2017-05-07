RM = rm -f
SHELL = bash
MAKE = make
ECHO = echo

CC = gcc

EXTRA_CFLAGS +=

CFLAGS = -g -O3 -Werror -Wall -Wno-strict-aliasing $(EXTRA_CFLAGS)

FLAGS =

INCS = -I..

LIBS = -L. -lev -lm

SERVER_BIN = natcapd_server
SERVER_CFLAGS = 
CLIENT_BIN = natcapd_client
CLIENT_CFLAGS = -DNATCAP_CLIENT_MODE

SRCS = natcapd.c

.SUFFIXES: .c .o .server.o .client.o
.c.server.o:
	$(CC) -c $*.c -o $*.server.o $(CFLAGS) $(SERVER_CFLAGS) $(INCS)

.c.client.o:
	$(CC) -c $*.c -o $*.client.o $(CFLAGS) $(CLIENT_CFLAGS) $(INCS)

default: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SRCS:.c=.server.o)
	$(CC) $^ -o $@ $(FLAGS) $(LIBS)

$(CLIENT_BIN): $(SRCS:.c=.client.o)
	$(CC) $^ -o $@ $(FLAGS) $(LIBS)

clean:
	$(RM) $(SERVER_BIN) $(CLIENT_BIN) $(SRCS:.c=.server.o) $(SRCS:.c=.client.o)

