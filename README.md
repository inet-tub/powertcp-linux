# PowerTCP for Linux
A proof of concept implementation of the PowerTCP congestion control algorithm
for Linux.

Based on the algorithm developed in:  
> Addanki, V., O. Michel, and S. Schmid.  
> “PowerTCP: Pushing the Performance Limits of Datacenter Networks.”  
> *19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 22).*  
> USENIX Association, 2022.

Available at [arXiv:2112.14309](https://arxiv.org/pdf/2112.14309.pdf).

This repository contains two implementations of the algorithm: a kernel module
and an eBPF program.

Both implementations provide the two variants of the PowerTCP algorithm as
separate congestion control algorithms: `powertcp` and `rttpowertcp` from the
kernel module, `bpf_powertcp` and `bpf_rttpowertcp` from the eBPF program.
Enable an algorithm system-wide with
```console
root@host:PowerTCP-Kernel-Module# echo powertcp > /proc/sys/net/ipv4/tcp_congestion_control
```
or use it with e.g. `iperf --tcp-congestion powertcp` or
`iperf3 --congestion powertcp`.

Read the [step-by-step instructions](doc/step-by-step.md) for an introduction
on how to use and experiment with the implementation. For further information,
see [README.md](README.md), [bpf/README.md](bpf/README.md),
[tools/README.md](tools/README.md), and [doc/](doc).

## Kernel Module
### Building
To build the kernel module, `make` and kernel headers for the target kernel
need to be installed. In a Debian-based distribution, the headers for the
running kernel are commonly available in a package named
`linux-headers-$(uname -r)`. The module can be build with a simple
```console
user@host:PowerTCP-Kernel-Module$ make
```

The kernel module is [prepared](dkms.conf) for system-wide installation through
DKMS. This also requires appropriate kernel headers (see above) and DKMS,
commonly available in a package of the same name. The [Makefile](Makefile)
provides a convenience target for installation through DKMS:
```console
root@host:PowerTCP-Kernel-Module# make dkms_install
```

### Tracepoints
There are
[tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html) to
follow the algorithm, mainly for the three core functions defined in the paper
and the values used and returned by them. The tracepoints can be found in
`/sys/kernel/debug/tracing/events/powertcp`.

They can be enabled for example (see
[Event Tracing](https://www.kernel.org/doc/html/latest/trace/events.html)) with
```console
root@host:~# echo 1 > /sys/kernel/debug/tracing/events/powertcp/enable
```
and shown with
```console
root@host:~# cat /sys/kernel/debug/tracing/trace_pipe
```
or used with any other of the available tools, like
[bpftrace](https://github.com/iovisor/bpftrace).

### Development Resources
 - [Kernel Build System: Building External Modules](https://www.kernel.org/doc/html/latest/kbuild/modules.html)

## eBPF Program
See [bpf/README.md](bpf/README.md).

## Implementation Details
There is *some* documentation on aspects of the implementation(s) in
[doc/](doc/).
