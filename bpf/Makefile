BPFTOOL ?= /usr/sbin/bpftool
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
VMLINUX ?= /sys/kernel/btf/vmlinux
TCP_INT_DIR ?= tcp-int/code

HAVE_WRITABLE_SK_PACING ?= 0
USE_SWLAT_AS_TIMESTAMP ?= 0

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

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

BPF_CFLAGS := -g -target bpf -D__TARGET_ARCH_$(ARCH) \
		  $(LIBBPF_CFLAGS) -c -O2 \
		  -mcpu=v3 -Wall -DHAVE_WRITABLE_SK_PACING=$(HAVE_WRITABLE_SK_PACING) \
		  -DUSE_SWLAT_AS_TIMESTAMP=$(USE_SWLAT_AS_TIMESTAMP) \
		  -I.. -I$(TCP_INT_DIR)/include
CXXFLAGS := -std=gnu++17 -O3 -Wall -Wextra $(LIBBPF_CFLAGS) -I.. -I$(TCP_INT_DIR)/src/tools
DEP_CFLAGS := -M -MG -I.. -I$(TCP_INT_DIR)/include
LDLIBS := $(LIBBPF_LIBS)

.PHONY: all
all: $(BPF_OBJS) $(PROGS) tcp_int

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

$(PROGS): CC=$(CXX)

$(PROG_DEPS): DEP_CFLAGS += -I$(TCP_INT_DIR)/src/tools

$(BPF_DEPS): %.d: %.c
	$(CC) $(DEP_CFLAGS) $< -MF $@

$(PROG_DEPS): %.d: %.cpp
	$(CXX) $(DEP_CFLAGS) $< -MF $@

.PHONY: tcp_int
tcp_int:
	env --unset=VMLINUX_H $(MAKE) -C tcp-int/code/src

ifneq ($(MAKECMDGOALS),clean)
-include $(BPF_DEPS) $(PROG_DEPS)
endif
