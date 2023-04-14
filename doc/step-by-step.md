# Step-by-step instructions

Following are step-by-step instructions on how to use and experiment with both
PowerTCP implementations.

For more information on the tools and scripts used here, see
[README.md](../README.md), [bpf/README.md](../bpf/README.md),
[tools/README.md](../tools/README.md), and [doc/](../doc).

*All commands listed here should be executed in the root folder of this
repository.*

## After checkout
After checking out this repository, initialize the Git submodules:
```
git submodule update --init
```

## Use the BPF implementation

### Preparation

The preparation steps need to be executed on both client and server.

Install required packages (as root/with `sudo`):
```
apt install '~n^bpftool$|~n^linux-tools-common$' clang g++ gcc libbpf-dev llvm make
```

Optionally tune the network interface for low latency etc. (as root/with
`sudo`):
```
apt install ethtool procps tuned
./tools/tune-eth IFACE
```

Build the PowerTCP BPF implementation and TCP-INT:
```
make -C bpf/
```
If you are using the modified TCP-INT P4 application that replaces the `swlat`
telemetry field with a timestamp, append `USE_SWLAT_AS_TIMESTAMP=1`:
```
make -C bpf/ USE_SWLAT_AS_TIMESTAMP=1
```

### On the server

*Close any previously opened screen sessions that were opened this way.*

Start `iperf` and `iperf3` server instances, ready to use PowerTCP, in a screen
session (as root/with `sudo`):
```
./tools/setup-bpf iperf-servers
```
**Beware: You are root user inside the screen session!**

Algorithm parameters (see [On the client](#on-the-client)) do not need to be
set on the server, they are irrelevant here.

### On the client

On the client, you can use PowerTCP in an interactive session or automatically
record traces of the algorithms execution.

#### Interactive usage

*Close any previously opened screen sessions that were opened this way.*

Open a screen session readily prepared to use PowerTCP (as root/with `sudo`):
```
./tools/setup-bpf iperf-client
```
**Beware: You are root user inside the screen session!**

You can and should pass algorithm parameters to the `setup-bpf` script, e.g (as
root/with `sudo`):
```
./tools/setup-bpf iperf-client tracing host_bw=25000 hop_bw=25000 base_rtt=50
```
For a list of the available parameters see 
```
./bpf/powertcp -h
```

Inside the screen session, you can, e.g,
- run `iperf3` (or `iperf`, the options differ)
  ```
  iperf3 -NZ -C bpf_powertcp -c SERVER_IP
  iperf3 -NZ -C bpf_rttpowertcp -c SERVER_IP
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

#### Record traces

*To record a trace, close any previously opened screen sessions opened for
[interactive usage](#interactive-usage).*

Record traces (as CSV files) of running `iperf3` with multiple **combinations**
of algorithm parameters (as root/with sudo):
```
./tools/bpf_tracer -NZ -c SERVER_IP -C bpf_powertcp -- host_bw=25000 hop_bw=20000 base_rtt=50 beta="2 10" gamma="0.5 0.9"
```

`bpf_tracer` takes `iperf3` options followed by PowerTCP algorithm parameters,
separated by a `--`:
```
./tools/bpf_tracer IPERF3_OPTS -- POWERTCP_PARAMS
```
`IPERF3_OPTS` can contain any `iperf3` *client* options; *it must specify the
congestion control algorithm to use*.

`POWERTCP_PARAMS` can contain any of the parameters listed by
`./bpf/powertcp -h`. Multiple values can be given for each parameter (as a
quoted string).

The above example call produces 4 CSV files:
```
bpf_powertcp-gamma=0.5 base_rtt=50 hop_bw=20000 beta=10 host_bw=25000.csv
bpf_powertcp-gamma=0.5 base_rtt=50 hop_bw=20000 beta=2 host_bw=25000.csv
bpf_powertcp-gamma=0.9 base_rtt=50 hop_bw=20000 beta=10 host_bw=25000.csv
bpf_powertcp-gamma=0.9 base_rtt=50 hop_bw=20000 beta=2 host_bw=25000.csv
```

## Use the module implementation

Note: There is no source for telemetry implemented in the module (the
integration is prepared, though). Only `rttpowertcp` is functional.

### Preparation

The preparation steps need to be executed on both client and server.

Install required packages (as root/with `sudo`):
```
apt install gcc linux-headers-$(uname -r) make
```

Optionally tune the network interface for low latency etc. (as root/with
`sudo`):
```
apt install ethtool procps tuned
./tools/tune-eth IFACE
```

Build the PowerTCP module implementation:
```
make
```

### On the server

*Close any previously opened screen sessions that were opened this way.*

Start `iperf` and `iperf3` server instances, ready to use PowerTCP, in a screen
session (as root/with `sudo`):
```
./tools/setup-module iperf-servers
```
**Beware: You are root user inside the screen session!**

Algorithm parameters (see [On the client](#on-the-client-1)) do not need to be
set on the server, they are irrelevant here.

### On the client

Open a screen session readily prepared to use PowerTCP (as root/with `sudo`):
```
./tools/setup-module iperf-client
```
**Beware: You are root user inside the screen session!**

You can and should pass algorithm parameters to the `setup-module` script, e.g (as
root/with `sudo`):
```
./tools/setup-module iperf-client host_bw=25000 hop_bw=25000 base_rtt=50
```
For a list of the available parameters see
```
/sbin/modinfo tcp_powertcp.ko
```
Note that a value for the gamma parameter must be multiplied with the value of
`power_scale` defined in [powertcp_defs.h](powertcp_defs.h) and rounded to an
integer afterwards.

Inside the screen session, you can, e.g,
- run `iperf3` (or `iperf`, the options differ)
  ```
  iperf3 -NZ -C rttpowertcp -c SERVER_IP
  ```
- TODO: Describe tracepoints.
