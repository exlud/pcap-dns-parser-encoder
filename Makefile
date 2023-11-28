CC=g++
LDFLAGS= -lpcap -lc

SUBDIRS = protocol collector learner

OBJS = build/dns.o build/collector.o build/learner.o

.PHONY: ${SUBDIRS} 

all: ${SUBDIRS}
	-@${CC} ${OBJS} main.cpp -o demo ${LDFLAGS} 

${SUBDIRS}:
	-@$(MAKE) -C $@

clean:
	@-rm -f build/*.o build/a.out 
	@-rm -f demo 

test:
	-@${MAKE} -C tests 
