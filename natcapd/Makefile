INCS += -I..
LIBS += -L. -lev -lm

SERVER_BIN = natcapd-server
CLIENT_BIN = natcapd-client

SERVER_CFLAGS = 
CLIENT_CFLAGS = -DNATCAP_CLIENT_MODE

SRCS = natcapd.c

.SUFFIXES: .c .o .server.o .client.o

.c.server.o:
	$(CC) -c $^ -o $@ $(CFLAGS) $(SERVER_CFLAGS) $(INCS)

.c.client.o:
	$(CC) -c $^ -o $@ $(CFLAGS) $(CLIENT_CFLAGS) $(INCS)

default: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SRCS:.c=.server.o)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

$(CLIENT_BIN): $(SRCS:.c=.client.o)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

clean:
	$(RM) $(SERVER_BIN) $(CLIENT_BIN) $(SRCS:.c=.server.o) $(SRCS:.c=.client.o)

