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

dkms_package_version := $(shell awk -F= '$$1 == "PACKAGE_VERSION" { gsub("\"", "", $$2); print $$2 }' dkms.conf)

.PHONY: dkms_install
dkms_install:
	dkms install .

.PHONY: dkms_uninstall
dkms_uninstall:
	dkms remove --all powertcp/$(dkms_package_version)
	$(RM) -r /usr/src/powertcp-$(dkms_package_version)

endif
