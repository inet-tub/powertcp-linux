# PowerTCP-Kernel-Module
A proof of concept implementation of PowerTCP within Linux Kernel

Based on the algorithm developed in:  
Addanki, V., O. Michel, and S. Schmid.  
“PowerTCP: Pushing the Performance Limits of Datacenter Networks.”  
*19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 22).*  
USENIX Association, 2022.

Available at [arXiv:2112.14309](https://arxiv.org/pdf/2112.14309.pdf).

## Tracepoints
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

## Development Resources
 - [Kernel Build System: Building External Modules](https://www.kernel.org/doc/html/latest/kbuild/modules.html)
