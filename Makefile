# build modules
#EXTRA_CFLAGS = -Wall
obj-m += natcap.o

natcap-y += natcap_main.o natcap_common.o natcap_client.o natcap_server.o natcap_forward.o

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

clean:
	$(KMAKE) clean
