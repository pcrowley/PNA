PROGRAM := pna_pcap
HASHMAP_DEPS := pna_hashmap.o murmur3.o monitor.o

CXXFLAGS := -I../include
LDLIBS := -lpcap

all: ${PROGRAM}

debug: CFLAGS += -ggdb
debug: ${PROGRAM}

${PROGRAM}: ${HASHMAP_DEPS}

clean:
	rm -f ${PROGRAM} *.o
