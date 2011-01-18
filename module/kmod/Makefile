
MOD = nf_ses_watch

obj-m := ${MOD}.o
cc_api-objs := ${MOD}.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) -I$(IDIR) modules

clean:
	rm -f *.o *.ko *~ *.mod.c
	rm -f .*o.cmd *.symvers
	rm -rf .tmp_versions
	rm -rf modules.order
