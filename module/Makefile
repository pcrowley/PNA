# kernel module files
obj-m += pna.o
pna-objs := pna_main.o pna_config.o pna_flowmon.o
pna-objs += pna_rtmon.o pna_rtmon-conlip.o pna_alerts.o

KDIR := /lib/modules/`uname -r`/build
EXTRA_CFLAGS += -I$(PWD)/../include/

ifdef piped
EXTRA_CFLAGS += -DPIPELINE_MODE=1
endif

all: module $(user-progs)

module:
	$(MAKE) -C $(KDIR) M=`pwd` modules

piped:
	$(MAKE) piped=1

clean:
	$(MAKE) -C $(KDIR) M=`pwd` clean
	rm -f Module.markers

