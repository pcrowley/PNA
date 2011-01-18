
PYX_FILES = model parse

CYTHON = cython
CC = gcc

CFLAGS = -shared -pthread -fPIC -fwrapv -O2 -Wall -fno-strict-aliasing
INCLUDES = -I/usr/local/include/python2.5/

all: ${PYX_FILES:%=%.so}

%.c: %.pyx
	$(CYTHON) $^

%.so: %.c
	$(CC) ${CFLAGS} ${INCLUDES} -o $@ $^

clean:
	rm -f ${PYX_FILES:%=%.c} ${PYX_FILES:%=%.so} *.pyc
