MODULE_NAME :=netlink_test
obj-m :=$(MODULE_NAME).o

CURRENT_PATH :=$(shell pwd)
VERSION_NUM :=$(shell uname -r)
LINUX_PATH :=/usr/src/linux-headers-$(VERSION_NUM)
all:kernel_module
	@echo "Make done!"
clean : clean_user clean_kernel
	@echo "Clean done!"

kernel_module:
	make -C $(LINUX_PATH) M=$(CURRENT_PATH) modules

user_module:
	gcc userspace.c -o userspace.exe
clean_user:
	-rm userspace.exe

clean_kernel:
	make -C $(LINUX_PATH) M=$(CURRENT_PATH) clean

#
#Desgin of Netlink
#

#MODULE_NAME :=netlink_test
#obj-m :=$(MODULE_NAME).o

#KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#PWD := $(shell pwd)

#all:
#    $(MAKE) -C $(KERNELDIR) M=$(PWD)

#clean:
#    $(MAKE) -C $(KERNELDIR) M=$(PWD) clean