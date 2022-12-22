# Code structure for module and BPF implementation

This is the common code structure for the module’s `tcp_powertcp.c` and the BPF
implementation’s `powertcp.bpf.c`. It uses direct `#include`s of source files
(instead of using multiple compilation units with headers) to enable full
inlining and other optimizations for both the module and BPF implementation.

The parts *must* appear in this order:

1. General `#include`s, including the required `linux/types.h` (module) or
   `vmlinux.h` (BPF)

2. An `#include` defining INT-related values and types in this order:
   1. Provide `max_n_hops` as an enumerator

   2. `#include "powertcp_int.c"` which provides `struct powertcp_int`
	  (requires `max_n_hops`) and other structs

   3. Provide a typedef for `powertcp_int_impl_t`, which can alias e.g. a
	  struct or a pointer, and constants `max_ts` and `max_tx_bytes`

   This include should be named `tcp_powertcp_METHOD_head.c` resp.
   `powertcp_METHOD_head.bpf.c`, e.g. `tcp_powertcp_foobar_head.c` or
   `powertcp_tcp-int_head.bpf.c`.

   `powertcp_no-int_head.c` shows the required content of this file.

3. `#define`s for various `POWERTCP_*` macros as needed; their default values
   are defined in `powertcp_head.c`

4. `#include "powertcp_head.c"` providing the core `struct powertcp` (requires
   `powertcp_int_impl_t`), the variables for the algorithm parameters, and
   default `#define`s for the still undefined `POWERTCP_*` macros

5. Additional (algorithm) parameter variables, other static/constant variables

6. Definitions of the required, module- or BPF-specific functions

7. An `#include` defining the INT-related functions

   This include should be named `tcp_powertcp_METHOD.c` resp.
   `powertcp_METHOD.bpf.c`, e.g. `tcp_powertcp_foobar.c` or
   `powertcp_tcp-int.bpf.c`.

   `powertcp_no-int.c` shows the required content of this file.

8. `#include "powertcp.c"` of the algorithm implementation

9. Additional definitions of functions requiring the PowerTCP
   `tcp_congestion_ops` instances, e.g. `module_init` and `module_exit`
