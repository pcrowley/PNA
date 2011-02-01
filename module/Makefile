# kernel module files
obj-m += pna.o
pna-objs := pna-kmod.o hooks.o alert.o

# user-space programs
ULOGGER := pna-logger
UALERTS := pna-alerts

###
KERNELDIR := /lib/modules/`uname -r`/build

all: module $(ULOGGER) $(UALERTS)

module:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules

$(ULOGGER): $(ULOGGER).c
	$(CC) -o $@ $^

$(UALERTS): $(UALERTS).c
	$(CC) -o $@ $^

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean
	rm -f Module.markers
	rm -f $(ULOGGER) $(UALERTS)
