CC=gcc
LDFLAGS= -lpcap -lc

all: run

run: psmoke
	-@./psmoke	
	-@rm *.o psmoke

psmoke: dns.o protocol_smoke_test.c
	@${CC} -o $@ $? ${LDFLAGS}

dns.o:
	@${CC} -c ../protocol/dns.c 

