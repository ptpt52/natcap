# build modules
#EXTRA_CFLAGS = -Wall
obj-m += natcap.o

natcap-y += natcap_main.o natcap_common.o natcap_client.o natcap_server.o natcap_forward.o natcap_knock.o natcap_peer.o

EXTRA_CFLAGS += -Wall -Werror

ifdef NO_DEBUG
EXTRA_CFLAGS += -Wno-unused -Os -DNO_DEBUG
endif

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

apnic.txt:
	wget https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest -O apnic.txt.tmp
	@mv apnic.txt.tmp apnic.txt
	@touch apnic.txt

cniplist.orig.set: apnic.txt
	cat apnic.txt | grep CN | grep ipv4 | cut -d\| -f4,5 >cniplist.txt.tmp
	lua apnic.lua cniplist.txt.tmp | while read line; do $$line | grep -v deaggregate; done >cniplist.orig.set.tmp
	@rm -f cniplist.txt.tmp
	@mv cniplist.orig.set.tmp cniplist.orig.set

