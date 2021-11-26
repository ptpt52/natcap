# build modules
#EXTRA_CFLAGS = -Wall
obj-m += natcap.o

natcap-y += natcap_main.o natcap_common.o natcap_client.o natcap_server.o natcap_knock.o natcap_peer.o

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

cniplist.set: cniplist.orig.set local.set sub.set ipops.lua
	lua ipgroup_merge.lua cniplist.orig.set local.set >cniplist.set.tmp
	lua ipgroup_sub.lua cniplist.set.tmp sub.set >cniplist.set
	@rm -f cniplist.set.tmp

C_cniplist.set: cniplist.set local.set sub.set ipops.lua
	lua ipgroup_invert.lua cniplist.set >C_cniplist.orig.set.tmp
	lua ipgroup_merge.lua C_cniplist.orig.set.tmp local.set >C_cniplist.set.tmp
	lua ipgroup_sub.lua C_cniplist.set.tmp sub.set >C_cniplist.set
	@rm -f C_cniplist.orig.set.tmp C_cniplist.set.tmp

ipset: cniplist.set C_cniplist.set cniplist6.set getflix.set hkiplist.orig.set

ip.merge.txt:
	wget -4 https://github.com/lionsoul2014/ip2region/raw/master/data/ip.merge.txt -O ip.merge.txt.tmp
	@mv ip.merge.txt.tmp ip.merge.txt

ipops.lua:
	wget -4 https://raw.githubusercontent.com/x-wrt/com.x-wrt/master/lua-ipops/src/ipops.lua -O ipops.lua.tmp
	@mv ipops.lua.tmp ipops.lua

apnic.txt:
	wget -4 https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest -O apnic.txt.tmp
	@mv apnic.txt.tmp apnic.txt
	@touch apnic.txt

cniplist.orig.set: cnip2cidr.lua ipops.lua ip.merge.txt apnic.txt
	lua cnip2cidr.lua >cniplist.orig.set
	cat apnic.txt | grep CN | grep ipv4 | cut -d\| -f4,5 >cniplist.txt.tmp
	lua apnic.lua cniplist.txt.tmp >>cniplist.orig.set
	@rm -f cniplist.txt.tmp
	lua ipgroup_merge.lua cniplist.orig.set >cniplist.orig.set.tmp
	@mv cniplist.orig.set.tmp cniplist.orig.set

hkiplist.orig.set: apnic.txt ipops.lua
	cat apnic.txt | grep HK | grep ipv4 | cut -d\| -f4,5 >hkiplist.txt.tmp
	lua apnic.lua hkiplist.txt.tmp >hkiplist.orig.set.tmp
	@rm -f hkiplist.txt.tmp
	@mv hkiplist.orig.set.tmp hkiplist.orig.set

cniplist6.orig.set: apnic.txt
	cat apnic.txt | grep ipv6 | grep CN | cut -d\| -f4,5 | sed 's,|,/,' >cniplist6.orig.set.tmp
	@mv cniplist6.orig.set.tmp cniplist6.orig.set

cniplist6.set: cniplist6.orig.set local6.set
	cat local6.set cniplist6.orig.set >cniplist6.set.tmp
	@mv cniplist6.set.tmp cniplist6.set

getflix.set:
	wget https://raw.githubusercontent.com/QiuSimons/Netflix_IP/master/getflix.txt -O getflix.set

dubai.set:
	wget https://raw.githubusercontent.com/uku/Unblock-Youku/master/shared/urls.js -O urls.js
	sh dubai.set.sh
