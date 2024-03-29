CC = g++
LDFLAGS = -lpcap -lc
CPPFLAGS = -I header

SUBDIRS = protocol src 

OBJS = build/dns.o build/stream.o build/streams.o

.PHONY: $(SUBDIRS) 

all: $(SUBDIRS)
	-@$(CC) $(OBJS) $(CPPFLAGS) main.cpp -o demo $(LDFLAGS) 
	-@$(CC) $(OBJS) $(CPPFLAGS) conditional.cpp -o conditional $(LDFLAGS) 
	-@$(CC) $(OBJS) $(CPPFLAGS) hops.cpp -o hops $(LDFLAGS) 
	-@$(CC) $(OBJS) $(CPPFLAGS) review.cpp -o review $(LDFLAGS) 

$(SUBDIRS):
	-@$(MAKE) -C $@

clean:
	@-rm -f build/*.o build/a.out 
	@-rm -f demo conditional hops review

test:
	-@$(MAKE) -C tests 
