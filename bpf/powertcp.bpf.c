// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * PowerTCP congestion control
 *
 * Based on the algorithm developed in:
 *    Addanki, V., O. Michel, and S. Schmid.
 *    "PowerTCP: Pushing the Performance Limits of Datacenter Networks."
 *    19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 22).
 *    USENIX Association, 2022.
 * Available at: https://arxiv.org/pdf/2112.14309.pdf
 *
 * Implemented by:
 *   Jörn-Thorben Hinz, TU Berlin, 2022.
 */

#include "bpf_ca_helpers.h"
#include "powertcp_defs.h"

#include "vmlinux.h"

#include "../powertcp_trace.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual MIT/GPL";

#define ULONG_MAX (-1UL)

#define POWERTCP_CONG_OPS_ATTRS SEC(".struct_ops")
#define POWERTCP_CONG_OPS_FUNC(name, ...)                                      \
	SEC("struct_ops/" __stringify(name))                                   \
	BPF_PROG(name, __VA_ARGS__)
#define POWERTCP_CONG_OPS_FUNC_PTR (void *)
#define POWERTCP_CONG_OPS_NAME_PREFIX bpf_

/* Configuration variables can only be set before loading the BPF object: */
#define POWERTCP_PARAM_ATTRS const volatile

#include "powertcp_tcp-int_head.bpf.c"

#include "../powertcp_head.c"

POWERTCP_PARAM_ATTRS bool tracing = false;

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} trace_events SEC(".maps");

/* Look for the host bandwidth (in Mbit/s). */
static unsigned long get_host_bw(struct sock *sk)
{
	return host_bw;
#if 0
	const struct dst_entry *dst = sk->sk_dst_cache;
	unsigned long bw = fallback_host_bw;

	if (dst && dst->dev) {
		struct ethtool_link_ksettings cmd;
		int r;

		rtnl_lock();
		/* ethtool_params_from_link_mode() would be even simpler.
		 * But dst->dev->link_mode seems to always be 0 at this point. */
		r = __ethtool_get_link_ksettings(dst->dev, &cmd);
		rtnl_unlock();
		if (r == 0 && cmd.base.speed != SPEED_UNKNOWN) {
			bw = cmd.base.speed;
			pr_debug("hash=%u: got link speed: %lu Mbit/s\n",
				 sk->sk_hash, bw);
		} else {
			pr_warn("link speed unavailable, using fallback: %lu Mbit/s\n",
				bw);
		}
	}

	return bw;
#endif
}

static void output_trace_event(struct powertcp_trace_event *trace_event)
{
	trace_event->time = bpf_ktime_get_ns();
	bpf_ringbuf_output(&trace_events, trace_event, sizeof(*trace_event), 0);
}

static void require_pacing(struct sock *sk)
{
	/* When using a kernel version before 6.0 that is manually patched with
	 * https://lore.kernel.org/all/20220622191227.898118-2-jthinz@mailbox.tu-berlin.de/,
	 * writing to sk_pacing_* can be enabled with HAVE_WRITABLE_SK_PACING=1
	 * passed to make.
	 */
	if (HAVE_WRITABLE_SK_PACING ||
	    LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 0, 0)) {
		/* We do want sk_pacing_rate to be respected: */
#if __clang_major__ >= 12
		// cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
		__sync_bool_compare_and_swap(&sk->sk_pacing_status,
					     SK_PACING_NONE, SK_PACING_NEEDED);
#else
		if (sk->sk_pacing_status == SK_PACING_NONE) {
			sk->sk_pacing_status = SK_PACING_NEEDED;
		}
#endif
	}
}

/* Set the socket pacing rate (bytes per second). */
static void set_rate(struct sock *sk, unsigned long rate)
{
	/* When using a kernel version before 6.0 that is manually patched with
	 * https://lore.kernel.org/all/20220622191227.898118-2-jthinz@mailbox.tu-berlin.de/,
	 * writing to sk_pacing_* can be enabled with HAVE_WRITABLE_SK_PACING=1
	 * passed to make.
	 *
	 * With an older and unpatched kernel, it is impossible to control
	 * sk_pacing_rate here from BPF code.
	 */
	if (HAVE_WRITABLE_SK_PACING ||
	    LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 0, 0)) {
		sk->sk_pacing_rate = min(rate, sk->sk_max_pacing_rate);
	}
}

static bool tracing_enabled()
{
	return tracing;
}

void POWERTCP_CONG_OPS_FUNC(powertcp_cong_avoid, struct sock *sk, u32 ack,
			    u32 acked)
{
	/* Before, tcp_congestion_ops.cong_avoid was non-optional in
	 * net/ipv4/bpf_tcp_ca.c, even if it is never used when cong_control is
	 * also set. This was fixed in Linux 6.0 with
	 * https://lore.kernel.org/all/20220622191227.898118-3-jthinz@mailbox.tu-berlin.de/.
	 *
	 * This stub is kept here for compatibility with older kernels.
	 */
}

#include "powertcp_tcp-int.bpf.c"

#include "../powertcp.c"
