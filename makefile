LDLIBS=-lpcap

all: tcp_block

tcp_block: mac.o ip.o main.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp_block *.o