CC = g++
LDFLAGS = -lpcap -lc
CPPFLAGS = -I header

SUBDIRS = protocol src 

OBJS = build/dns.o build/stream.o build/streams.o

.PHONY: $(SUBDIRS) 

all: $(SUBDIRS)
	-@$(CC) $(OBJS) $(CPPFLAGS) main.cpp -o demo $(LDFLAGS) 

$(SUBDIRS):
	-@$(MAKE) -C $@

clean:
	@-rm -f build/*.o build/a.out 
	@-rm -f demo 

test:
	-@$(MAKE) -C tests 
