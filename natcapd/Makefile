RM = rm -f
SHELL = bash
MAKE = make
ECHO = echo

CC = gcc

CFLAGS = -g -O3 -Werror -Wall -Wno-strict-aliasing

FLAGS =

INCS = -I../

LIBS = -L./ -lev -lm

BIN = natcapd

SRCS = natcapd.c

.SUFFIXES: .c .o .test.o
.c.o:
	$(CC) -c $*.c -o $*.o $(CFLAGS) $(INCS)

default: binary

binary: $(SRCS:.c=.o)
	$(CC) $^ -o $(BIN) $(FLAGS) $(LIBS)

clean:
	$(RM) $(BIN) $(SRCS:.c=.o)

