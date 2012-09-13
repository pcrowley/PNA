
progs := example_mon pcap_dump session

CFLAGS := -I ../../include
LDLIBS := -lpcap

all: $(progs)

$(progs): ../pna.o

session: ../session_dump.o ../proc_dump.o

clean:
	rm -f $(progs) *.o
