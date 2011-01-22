# kernel module files
obj-m += pna.o
pna-objs := pna-kmod.o hooks.o action.o

# user-space files
LOGGER := pna-logger

###
KERNELDIR := /lib/modules/`uname -r`/build

all: module logger

module:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules

logger:
	$(CC) -o $(LOGGER) $(LOGGER).c

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean
	rm -f Module.markers
	rm -f $(LOGGER)
