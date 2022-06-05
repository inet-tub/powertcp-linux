BPFTOOL ?= /usr/sbin/bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
VMLINUX ?= /sys/kernel/btf/vmlinux

HAVE_WRITABLE_SK_PACING ?= 0

BPF_OBJS := rtt_powertcp.bpf.o
BPF_DEPS := $(BPF_OBJS:.o=.d)
VMLINUX_H := vmlinux.h

# Copied from Linux' tools/scripts/Makefile.arch:
ARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
    -e s/sun4u/sparc/ -e s/sparc64/sparc/ \
    -e /arm64/!s/arm.*/arm/ -e s/sa110/arm/ \
    -e s/s390x/s390/ -e s/parisc64/parisc/ \
    -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
    -e s/sh[234].*/sh/ -e s/aarch64.*/arm64/ \
    -e s/riscv.*/riscv/)

CFLAGS += -g -target bpf -MD -D__TARGET_ARCH_$(ARCH) \
		  $(shell pkg-config --cflags libbpf) -c -O2 \
		  -mcpu=probe -Wall -DHAVE_WRITABLE_SK_PACING=$(HAVE_WRITABLE_SK_PACING)

.PHONY: all
all: $(BPF_OBJS)

.PHONY: clean
clean:
	$(RM) -r -- $(BPF_DEPS) $(BPF_OBJS) $(VMLINUX_H)

$(VMLINUX_H): $(VMLINUX)
	$(BPFTOOL) btf dump file $< format c > $@

%.bpf.o: %.bpf.c $(VMLINUX_H)
	$(CLANG) $(CFLAGS) $< -o $@
	$(LLVM_STRIP) -g $@

-include $(BPF_DEPS)
