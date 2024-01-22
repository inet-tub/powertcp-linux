# PowerTCP kernel module

> [!IMPORTANT]
> The kernel module is missing a source of telemetry (the integration is
> prepared). Therefore, the `powertcp` congestion control in the module is only a
> proof of concept.

> [!NOTE]
> The `rttpowertcp` in the kernel module is functional but—due to limitations
> in the kernel—lacks access to higher-precision hardware timestamps.

Following are step-by-step instructions on how to use and experiment with the
PowerTCP kernel module. All commands listed here are assumed to be executed in
the root folder of this repository.

When loaded into the kernel, the congestion control algorithms are called
`powertcp` and `rttpowertcp`.

## Prerequisites
- Any recent Linux kernel and corresponding kernel headers
- `gcc`
- `make`
- `dkms` (optional)

## Preparation

The preparation steps need to be executed on both client and server.

1. Install required packages (as root/with `sudo`):
   ```
   apt install gcc linux-headers-$(uname -r) make
   ```
   
   Optionally tune the network interface for low latency etc. (as root/with
   `sudo`):
   ```
   apt install ethtool procps tuned
   ./tools/tune-eth IFACE
   ```
2. Build the PowerTCP module implementation:
   ```
   make
   ```

## On the server

*Close any previously opened screen sessions that were opened this way.*

Start `iperf` and `iperf3` server instances, ready to use PowerTCP, in a screen
session (as root/with `sudo`):
```
./tools/setup-module iperf-servers
```
**Beware: You are root user inside the screen session!**

Algorithm parameters (see [On the client](#on-the-client)) do not need to be
set on the server, they are irrelevant here.

## On the client

The `setup-module` script opens a screen session readily prepared to use
PowerTCP.

You can and should pass algorithm parameters to `setup-module`, e.g (as
root/with `sudo`):
```
./tools/setup-module iperf-client host_bw=25000 hop_bw=25000 base_rtt=50
```
For a list of the available parameters see
```
/sbin/modinfo tcp_powertcp.ko
```
Note that a value for the `gamma` parameter must be multiplied with the value
of `power_scale` defined in [powertcp_defs.h](../powertcp_defs.h) and rounded
to an integer afterwards.

**Beware: You are root user inside the screen session!**

Inside the screen session, you can, e.g,
- run `iperf3` (or `iperf`, the options differ)
  ```
  iperf3 -N -C rttpowertcp -c SERVER_IP
  ```

## Installation through DKMS

The kernel module is [prepared](dkms.conf) for system-wide installation through
DKMS. The [Makefile](Makefile) provides a convenience target for installation
through DKMS (as root/with `sudo`):
```
make dkms_install
```

## Tracepoints
There are
[tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html) to
follow the algorithm, mainly for the three core functions defined in the
[paper](#for-powertcp) and the values used and returned by them. The tracepoints
can be found in `/sys/kernel/debug/tracing/events/powertcp`.

They can be enabled for example (see
[Event Tracing](https://www.kernel.org/doc/html/latest/trace/events.html)) with
(as root/with `sudo`)
```
echo 1 > /sys/kernel/debug/tracing/events/powertcp/enable
```
and shown with (as root/with `sudo`)
```
cat /sys/kernel/debug/tracing/trace_pipe
```
or used with any other of the available tools, like
[bpftrace](https://github.com/iovisor/bpftrace).

## Development Resources
 - [Kernel Build System: Building External Modules](https://www.kernel.org/doc/html/latest/kbuild/modules.html)
