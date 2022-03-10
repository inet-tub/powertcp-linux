ifneq ($(KERNELRELEASE),)

obj-m := tcp_powertcp.o

tcp_powertcp-y := tcp_powertcp_cong.o
tcp_powertcp-$(CONFIG_DEBUG_FS) += tcp_powertcp_debugfs.o

else

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: modules modules_install clean help
modules modules_install clean help:
	$(MAKE) -C $(KDIR) M=$$PWD $@

endif
