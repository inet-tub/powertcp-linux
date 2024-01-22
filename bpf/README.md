# PowerTCP eBPF implementation

> [!IMPORTANT]
> The `bpf_powertcp` congestion control is fully functional but requires TCP-INT
> to be deployed on your network switches. A description on how to deploy TCP-INT
> is unfortunately out of the scope of this repository. You can find a hint in
> the TCP-INT repository: [Switch Code](https://github.com/p4lang/p4app-TCP-INT/tree/v0.2.0-alpha#switch-code).

> [!NOTE]
> The `bpf_rttpowertcp` in the kernel module is functional but lacks access to
> higher-precision hardware timestamps (due to limitations in the kernel). This
> might change in upcoming kernel releases.

Following are step-by-step instructions on how to use and experiment with the
PowerTCP eBPF implementation. All commands listed here are assumed to be executed
in the root folder of this repository.

When loaded into the kernel, the congestion control algorithms are called
`bpf_powertcp` and `bpf_rttpowertcp`.

## Prerequisites

### In the network
- TCP-INT
  [deployed](https://github.com/p4lang/p4app-TCP-INT/tree/v0.2.0-alpha#switch-code)
  on network switches

### On the hosts
- Linux kernel 5.10 or above (ideally 6.0 or above)
- `bpftool` version 5.15 or above
- `clang` version 3.7 or above
- `g++` version 10 or above
- libbpf version 0.5 or above
- `llvm-strip`
- `make`

The required versions are available starting with Debian 10 (Bullseye) and Ubuntu
22.04 (Jammy Jellyfish).

The installation of the required software is shown in the following.

<details>
<summary><b>Details on the kernel requirements</b></summary>

The target kernel must be compiled with `CONFIG_DEBUG_INFO_BTF=y`. It usually
is, check with
```
grep -w CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
```

For optimal performance, the target kernel can be
[patched for `sk_pacing_rate` to be writable](https://lore.kernel.org/all/20220622191227.898118-2-jthinz@mailbox.tu-berlin.de/)
from eBPF code. This patch is included in kernel versions 6.0 and following, no
further action is required. If the target kernel is *manually* patched, enable
the usage of the pacing rate in the eBPF programs by appending
`HAVE_WRITABLE_SK_PACING=1` to the below invocation of `make`.

</details>

## After checkout
After checking out this repository, also checkout TCP-INT which is managed as a
Git submodule in the bpf/tcp-int/ subdirectory:
```
git submodule update --init
```

## Preparation

The preparation steps need to be executed on both client and server.

1. Install required packages (as root/with `sudo`):
   ```
   apt install 'bpftool|linux-tools-common$' clang g++ gcc libbpf-dev llvm make
   ```
   
   Ideally, tune the network interface *IFACE* for low latency etc. (as root/with
   `sudo`):
   ```
   apt install ethtool procps tuned
   ./tools/tune-eth IFACE
   ```
2. Build the PowerTCP BPF program and TCP-INT:
   ```
   make -C bpf/
   ```
   
   If you are using a modified TCP-INT P4 application that replaces the `swlat`
   telemetry field with a timestamp, append `USE_SWLAT_AS_TIMESTAMP=1` to the
   above invocation of `make`.
   
   Disable stripping of the object files (for more human-readable `objdump`
   output) by appending `LLVM_STRIP=/bin/true` to the above invocation of `make`.

## On the server

*Close any previously opened screen sessions that were opened this way.*

Start `iperf` and `iperf3` server instances, ready to use PowerTCP, in a screen
session (as root/with `sudo`):
```
./tools/setup-bpf iperf-servers
```
**Beware: You are root user inside the screen session!**

Algorithm parameters (see [On the client](#on-the-client)) do not need to be
set on the server, they are irrelevant here.

## On the client

> [!NOTE]
> Applications that want to use `bpf_powertcp` or `bpf_rttpowertcp` must be
> executed in the *tcp-int* cgroup. The `setup-bpf` script takes care of this.

On the client, you can use PowerTCP in an interactive session or automatically
record traces of the algorithm execution.

### Interactive usage

*Close any previously opened screen sessions that were opened this way.*

The `setup_bpf` script opens a screen session readily prepared to use PowerTCP.
Applications executed in this screen session are in the *tcp-int* cgroup, as
required.

You can pass algorithm parameters to `setup-bpf`. You should pass at least
`hop_bw` and `host_bw`, e.g (as root/with `sudo`):
```
./tools/setup-bpf iperf-client tracing host_bw=25000 hop_bw=25000 base_rtt=50
```
For a list of the available parameters see
```
./bpf/powertcp -h
```

**Beware: You are root user inside the screen session!**

Inside the screen session, you can, e.g,
- run `iperf3` (or `iperf`, the options differ)
  ```
  iperf3 -N -C bpf_powertcp -c SERVER_IP
  iperf3 -N -C bpf_rttpowertcp -c SERVER_IP
  ```
- or watch PowerTCP’s trace output
  ```
  ./bpf/powertcp trace
  ```
  (for CSV output append the option `-C`—or see [Record traces](#record-traces))
- or watch TCP-INT’s trace output
  ```
  ./bpf/tcp-int/code/src/tools/tcp_int trace
  ```
- or quickly setup PowerTCP with different parameters
  ```
  ./bpf/powertcp register -f tracing host_bw=100000 hop_bw=100000 base_rtt=50 gamma=0.7
  ```

### Record traces

*To record a trace, close any previously opened screen sessions opened for
[interactive usage](#interactive-usage).*

Record traces (as CSV files) of running `iperf`/`iperf3` with multiple
**combinations** of algorithm parameters (as root/with `sudo`):
```
./tools/bpf_tracer iperf3 -N -c SERVER_IP -C bpf_powertcp -- host_bw=25000 hop_bw=20000 base_rtt=50 beta="2 10" gamma="0.5 0.9"
```

`bpf_tracer` takes an `iperf`/`iperf3` command line followed by PowerTCP
algorithm parameters, separated by a `--`:
```
./tools/bpf_tracer IPERF(3)_CMDLINE -- POWERTCP_PARAMS
```
`IPERF(3)_CMDLINE` must contain a full `iperf`/`iperf3` *client* command line;
*it must specify the congestion control algorithm to use*.

`POWERTCP_PARAMS` can contain any of the parameters listed by
`./bpf/powertcp -h`. Multiple values can be given for each parameter as a
quoted string.

The above example call produces 4 CSV files:
```
bpf_powertcp-gamma=0.5 base_rtt=50 hop_bw=20000 beta=10 host_bw=25000.csv
bpf_powertcp-gamma=0.5 base_rtt=50 hop_bw=20000 beta=2 host_bw=25000.csv
bpf_powertcp-gamma=0.9 base_rtt=50 hop_bw=20000 beta=10 host_bw=25000.csv
bpf_powertcp-gamma=0.9 base_rtt=50 hop_bw=20000 beta=2 host_bw=25000.csv
```
