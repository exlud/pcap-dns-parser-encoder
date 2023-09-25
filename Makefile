CC=gcc
LDFLAGS= -lpcap -lc

all: parser

parser: parser.o cli.o
	@${CC} -o $@ $? ${LDFLAGS}

clean:
	@-rm -f parser.o cli.o parser

%.o: %.c
	@${CC} -c $< -o $@
