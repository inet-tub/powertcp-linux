BPFTOOL ?= /usr/sbin/bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
VMLINUX ?= /sys/kernel/btf/vmlinux
TCP_INT_DIR ?= tcp-int/code

HAVE_WRITABLE_SK_PACING ?= 0

BPF_OBJS := powertcp.bpf.o
BPF_DEPS := $(BPF_OBJS:.o=.d)
BPF_SKELS := $(BPF_OBJS:.bpf.o=.skel.h)
PROGS := powertcp
PROG_DEPS := $(PROGS:=.d)
PROG_OBJS := $(PROGS:=.o)
VMLINUX_H := vmlinux.h

# Copied from Linux' tools/scripts/Makefile.arch:
ARCH := $(shell uname -m | sed -e s/i.86/x86/ -e s/x86_64/x86/ \
    -e s/sun4u/sparc/ -e s/sparc64/sparc/ \
    -e /arm64/!s/arm.*/arm/ -e s/sa110/arm/ \
    -e s/s390x/s390/ -e s/parisc64/parisc/ \
    -e s/ppc.*/powerpc/ -e s/mips.*/mips/ \
    -e s/sh[234].*/sh/ -e s/aarch64.*/arm64/ \
    -e s/riscv.*/riscv/)

BPF_CFLAGS := -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		  $(shell pkg-config --cflags libbpf) -c -O2 \
		  -mcpu=probe -Wall -DHAVE_WRITABLE_SK_PACING=$(HAVE_WRITABLE_SK_PACING) \
		  -I$(TCP_INT_DIR)/include
CFLAGS := -O3 -Wall -Wextra $(shell pkg-config --cflags libbpf) -I$(TCP_INT_DIR)/src/tools
DEP_CFLAGS := -M -MG -I$(TCP_INT_DIR)/include
LDLIBS := $(shell pkg-config --libs libbpf)

.PHONY: all
all: $(BPF_OBJS) $(PROGS)

.PHONY: clean
clean:
	$(RM) $(BPF_DEPS) $(BPF_OBJS) $(BPF_SKELS) $(PROG_DEPS) $(PROG_OBJS) $(PROGS) $(VMLINUX_H)

$(VMLINUX_H): $(VMLINUX)
	$(BPFTOOL) btf dump file $< format c > $@

%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) $< -o $@
	$(LLVM_STRIP) -g $@

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(PROG_DEPS): DEP_CFLAGS += -I$(TCP_INT_DIR)/src/tools

$(BPF_DEPS) $(PROG_DEPS): %.d: %.c
	$(CC) $(DEP_CFLAGS) $< -MF $@

ifneq ($(MAKECMDGOALS),clean)
-include $(BPF_DEPS) $(PROG_DEPS)
endif
