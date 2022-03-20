ifneq ($(KERNELRELEASE),)

# Without explicitly specifying the source folder as an include dir,
# define_trace.h fails to find our trace header.
ccflags-y := -I$(src)

obj-m := tcp_powertcp.o

else

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: modules modules_install clean help
modules modules_install clean help:
	$(MAKE) -C $(KDIR) M=$$PWD $@

endif
