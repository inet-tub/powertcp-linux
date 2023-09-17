# `setup-bpf` and `setup-module`
The setup scripts prepare the BPF and module implementation of PowerTCP,
respectively, for usage. This includes (re)loading the implementation and its
prerequisites and opening a screen session for interactive usage, e.g. for
calling `iperf`/`iperf3`.

**The scripts must be called as root or with `sudo`.**

## Usage
```
setup-bpf SESSION_NAME [PARAMETER...]
setup-module SESSION_NAME [PARAMETER...]
```

### `SESSION_NAME`
Required. Name of a predefined screen session to open. Available sessions:
- `iperf-client`: Opens an empty screen session for `iperf`/`iperf3` *client*
  usage.
- `iperf-servers`: Opens a screen session with both `iperf` and `iperf3`
  servers readily running inside.

**Using PowerTCP and its prerequisites outside of the opened screen session
will require additional, manual setup steps (e.g., joining the TCP-INT cgroup
for the BPF implementation).**

### `PARAMETER`
Optional. One or multiple PowerTCP algorithm parameters. Available parameters:
- `base_rtt`: Base RTT in µs
- `beta`: Additive increase parameter in number of packets
- `hop_bw`: Link speed of the switches in Mbit/s
- `host_bw`: Link speed of the host in Mbit/s
- `expected_flows`: Expected number of flows on a link
- `gamma`: EWMA weight in range [0.0, 1.0]

Currently, parameter values passed to `setup-module` need to be scaled with the
constants defined in [powertcp_defs.h](../powertcp_defs.h). `setup-bpf` accepts
values in the units specified above.

Parameters can be set to different values from within the screen session
without calling `setup-bpf`
```console
root@host:powertcp-linux# ./bpf/powertcp -f register base_rtt=100 hop_bw=25000 host_bw=25000
```
or `setup-module` again
```console
root@host:powertcp-linux# ./tools/reinsmod base_rtt=100 hop_bw=25000 host_bw=25000
```

## Examples
```console
user@host:powertcp-linux$ ./tools/setup-bpf iperf-client base_rtt=123 hop_bw=100000 host_bw=100000
user@host:powertcp-linux$ ./tools/setup-bpf iperf-servers
user@host:powertcp-linux$ ./tools/setup-module iperf-client base_rtt=456 host_bw=10000
user@host:powertcp-linux$ ./tools/setup-module iperf-servers
```
