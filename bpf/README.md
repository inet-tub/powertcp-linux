# eBPF Implementation of PowerTCP
Tested with kernels 5.10 and 5.16.

# Building
Requires `bpftool`, `clang`, libbpf headers (version >= 0.7), `llvm-strip`, and
`make` to build.  (Packages `bpftool`, `clang`, `libbpf-dev`, `llvm`, and
`make` in a Debian-based distribution.)

The target kernel must be compiled with `CONFIG_DEBUG_INFO_BTF=y` (it usually
is).

Simply build with 
```console
user@host:~/bpf$ make
```
in this directory.

For optimal performance, the target kernel should be [patched for
`sk_pacing_rate` to be
writable](https://lore.kernel.org/all/20220622191227.898118-2-jthinz@mailbox.tu-berlin.de/)
from eBPF code. This patch is included in kernel versions 6.0 and following. If
the patch is included in the target kernel, enable the usage of the pacing rate
in the eBPF programs by appending `HAVE_WRITABLE_SK_PACING=1` to the invokation
of `make`.

Disable stripping of the object files (for more human-readable `objdump`
output) by appending `LLVM_STRIP=/bin/true` to the invokation of `make`.

# Loading
The compiled eBPF programs can be loaded into the kernel and registered as
congestion control algorithms with the provided `powertcp` tool:
```console
root@host:PowerTCP-Kernel-Module/bpf# ./powertcp register
```
