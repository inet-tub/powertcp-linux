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

#include "tcp_int_common.h"
#include "tcp_int_common.bpf.h"

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

enum { max_n_hops = 1 };

/* TCP-INT's swlat field (which we optionally replace with a timestamp), is
 * only 24 bits long.
 */
static const unsigned int max_ts = 0xFFFFFFu;

/* In case the tx_bytes value is taken directly from a less-than-32-bit INT
 * field, its maximum value has to be known for correct wrap-around in
 * calculations.
 */
static const __u32 max_tx_bytes = 0xFFFFFFFFu;

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

static const struct powertcp_int *get_int(struct sock *sk,
					  const struct powertcp_int *prev_int)
{
	struct ptcp_powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Not using tcp_int_get_state() here since it uses
	 * BPF_SK_STORAGE_GET_F_CREATE. We might want to use a missing map entry as
	 * an indicator to fall back to RTT-PowerTCP.
	 */
	const struct tcp_int_state *tint =
		bpf_sk_storage_get(&map_tcp_int_state, sk, NULL, 0);

	if (tint) {
		__u32 bandwidth = BITS_TO_BYTES(hop_bw);
#if USE_SWLAT_AS_TIMESTAMP
		__u32 ts = tint->swlat;
#else
		__u32 ts = tp->tcp_mstamp * NSEC_PER_USEC;
#endif
		__u32 dt = (!prev_int ? tp->srtt_us * (1000u >> 3) :
					      ts - prev_int->hops[0].ts) &
			   max_ts;

		ca->cached_int.n_hop = 1;
		/* TCP-INT does not provide an identification for the path. */
		/* TODO: Evaluate if it makes sense to use the switch ID as path ID.
		 * Could lead to a too frequently detected path change, though.
		 */
		ca->cached_int.path_id = 1;

		ca->cached_int.hops[0].bandwidth = bandwidth;
		ca->cached_int.hops[0].qlen = tint->qdepth;
		ca->cached_int.hops[0].ts = ts;
		/* In lack of a tx_bytes value, we estimate it here. A factor of
		 * MEGA/USEC_PER_SEC is cancelled in the calculation:
		 */
		ca->cached_int.hops[0].tx_bytes =
			bandwidth * tint->util / 100 / NSEC_PER_USEC * dt;

		return &ca->cached_int;
	} else {
		ca->cached_int.n_hop = 0;
	}

	return NULL;
}

static const struct powertcp_int *get_prev_int(struct sock *sk)
{
	struct ptcp_powertcp *ca = inet_csk_ca(sk);
	struct powertcp_int *prev_int = &ca->prev_int;

	if (prev_int->n_hop) {
		/* With TCP-INT, the difference in tx_bytes since last ACK is already
		 * estimated in get_int(). The previous value must be 0 so
		 * ptcp_norm_power() does not calculate a second difference with a
		 * value potentially coming from a different switch.
		 */
		prev_int->hops[0].tx_bytes = 0;
		return prev_int;
	}

	return NULL;
}

static void output_trace_event(struct powertcp_trace_event *trace_event)
{
	trace_event->time = bpf_ktime_get_ns() / NSEC_PER_USEC;
	bpf_ringbuf_output(&trace_events, &trace_event, sizeof(trace_event), 0);
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

void POWERTCP_CONG_OPS_FUNC(powertcp_cong_avoid, struct sock *sk, __u32 ack,
			    __u32 acked)
{
	/* Before, tcp_congestion_ops.cong_avoid was non-optional in
	 * net/ipv4/bpf_tcp_ca.c, even if it is never used when cong_control is
	 * also set. This was fixed in Linux 6.0 with
	 * https://lore.kernel.org/all/20220622191227.898118-3-jthinz@mailbox.tu-berlin.de/.
	 *
	 * This stub is kept here for compatibility with older kernels.
	 */
}

#include "../powertcp_impl.c"
