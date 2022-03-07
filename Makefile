ifneq ($(KERNELRELEASE),)

obj-m := tcp_powertcp.o

else

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: modules modules_install clean help
modules modules_install clean help:
	$(MAKE) -C $(KDIR) M=$$PWD $@

endif
