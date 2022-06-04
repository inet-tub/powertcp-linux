BPFTOOL ?= /usr/sbin/bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
VMLINUX ?= /sys/kernel/btf/vmlinux

HAVE_WRITABLE_SK_PACING ?= 0

BPF_OBJS := rtt_powertcp.bpf.o
INCLUDE_DIR := .include

# Copied from Linux' tools/scripts/Makefile.arch:
ARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
    -e s/sun4u/sparc/ -e s/sparc64/sparc/ \
    -e /arm64/!s/arm.*/arm/ -e s/sa110/arm/ \
    -e s/s390x/s390/ -e s/parisc64/parisc/ \
    -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
    -e s/sh[234].*/sh/ -e s/aarch64.*/arm64/ \
    -e s/riscv.*/riscv/)

CFLAGS += -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		  $(shell pkg-config --cflags libbpf) -I$(INCLUDE_DIR) -c -O2 \
		  -mcpu=probe -Wall -DHAVE_WRITABLE_SK_PACING=$(HAVE_WRITABLE_SK_PACING)

.PHONY: all
all: $(BPF_OBJS)

.PHONY: clean
clean:
	$(RM) -r -- $(INCLUDE_DIR) $(BPF_OBJS)

$(INCLUDE_DIR):
	mkdir $(INCLUDE_DIR)

$(INCLUDE_DIR)/vmlinux.h: Makefile | $(INCLUDE_DIR)
	$(BPFTOOL) btf dump file $(VMLINUX) format c > $@

%.bpf.o: %.bpf.c Makefile $(INCLUDE_DIR)/vmlinux.h
	$(CLANG) $(CFLAGS) $< -o $@
	$(LLVM_STRIP) -g $@
