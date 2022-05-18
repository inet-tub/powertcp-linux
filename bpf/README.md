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

If the target kernel is patched with `sk_pacing_rate` writable from eBPF code,
enable the usage of the pacing rate in the eBPF programs by appending
`HAVE_WRITABLE_SK_PACING=1` to the invokation of `make`.

Disable stripping of the object files (for more human-readable `objdump`
output) by appending `LLVM_STRIP=/bin/true` to the invokation of `make`.

# Loading
The compiled eBPF programs can be loaded into the kernel and registered for
congestion control with `bpftool`:
```console
root@host:~# bpftool struct_ops register rtt_powertcp.bpf.o
```

Set the congestion control with:
```console
root@host:~# echo bpf_rttpowertcp > /proc/sys/net/ipv4/tcp_congestion_control
```
