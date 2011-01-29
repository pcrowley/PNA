# kernel module files
obj-m += pna.o
pna-objs := pna-kmod.o hooks.o alert.o

# user-space programs
USER_PROGS := pna-logger pna-alerts

###
KERNELDIR := /lib/modules/`uname -r`/build

all: module $(USER_PROGS)

module:
	$(MAKE) -C $(KERNELDIR) M=`pwd` modules

$(USER_PROGS):
	$(CC) -o $@ $@.c

clean:
	$(MAKE) -C $(KERNELDIR) M=`pwd` clean
	rm -f Module.markers
	rm -f $(USER_PROGS)
