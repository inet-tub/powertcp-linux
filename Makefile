ifneq ($(KERNELRELEASE),)

obj-m := tcp_powertcp.o

else

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: modules clean
modules clean:
	$(MAKE) -C $(KDIR) M=$$PWD $@

endif
