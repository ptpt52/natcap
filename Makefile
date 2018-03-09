# build modules
#EXTRA_CFLAGS = -Wall
obj-m += natcap.o

natcap-y += natcap_main.o natcap_common.o natcap_client.o natcap_server.o natcap_forward.o natcap_knock.o

EXTRA_CFLAGS += -Wall -Werror

PWD ?= $(shell pwd)

ifndef KERNELRELEASE
KERNELRELEASE := $(shell uname -r)
endif
    
KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
KMAKE := $(MAKE) -C $(KERNELDIR) M=$(PWD)

all: modules

modules:
	$(KMAKE) modules

modules_install:
	$(KMAKE) modules_install

install: modules_install
	depmod

modules_clean:
	$(KMAKE) clean

clean: modules_clean

cniplist.set: cniplist.orig.set local.set
	lua ipgroup_merge.lua cniplist.orig.set local.set | while read line; do $$line | grep -v deaggregate; done >cniplist.set.tmp
	@mv cniplist.set.tmp cniplist.set

C_cniplist.set: cniplist.set local.set
	lua ipgroup_invert.lua cniplist.set | while read line; do $$line | grep -v deaggregate; done >C_cniplist.orig.set.tmp
	lua ipgroup_merge.lua C_cniplist.orig.set.tmp local.set | while read line; do $$line | grep -v deaggregate; done >C_cniplist.set.tmp
	@mv C_cniplist.set.tmp C_cniplist.set
	@rm -f C_cniplist.orig.set.tmp

ipset: cniplist.set C_cniplist.set
