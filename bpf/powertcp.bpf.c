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

#include "powertcp.bpf.h"

#include "tcp_int_common.h"
#include "tcp_int_common.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual MIT/GPL";

#define ULONG_MAX (-1UL)

enum { max_n_hops = 1 };

struct old_cwnd {
	__u32 snd_nxt;
	unsigned long cwnd;
};

struct powertcp_hop_int {
	__u32 bandwidth; /* in MByte/s */
	__u32 ts;
	__u32 tx_bytes;
	__u32 qlen;
};

struct powertcp_int {
	int n_hop;
	int path_id;
	struct powertcp_hop_int hops[max_n_hops];
};

struct powertcp {
	unsigned long base_rtt;
	unsigned long snd_cwnd;

	union {
		struct {
			struct powertcp_int cached_int;
			struct powertcp_int prev_int;
		} ptcp;
		struct {
			__u32 last_updated;
			unsigned long prev_rtt_us;
			__u64 t_prev;
		} rttptcp;
	};

	unsigned long beta;

	struct old_cwnd old_cwnd;

	unsigned long p_smooth;

	/* powertcp_cong_control() seems to (unexpectedly) get called once before
	 * powertcp_init(). host_bw is still 0 then, thanks to
	 * tcp_assign_congestion_control(), and we use that as an indicator whether
	 * we are initialized.
	 */
	unsigned long host_bw; /* Mbit/s */
};

/* Configuration variables only settable before loading the BPF object: */
const volatile long base_rtt = default_base_rtt;
const volatile long beta = default_beta;
const volatile long expected_flows = default_expected_flows;
const volatile long gamma = default_gamma;
const volatile long hop_bw = default_hop_bw; /* Mbit/s */
const volatile long host_bw = fallback_host_bw; /* Mbit/s */
const volatile bool tracing = false;

extern __u32 LINUX_KERNEL_VERSION __kconfig;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} trace_events SEC(".maps");

static void clear_old_cwnds(struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);
	ca->old_cwnd.cwnd = 0;
	ca->old_cwnd.snd_nxt = 0;
}

static unsigned long ewma(unsigned long weight, unsigned long weight_scale,
			  unsigned long value, unsigned long old_value)
{
	return (weight * value + (weight_scale - weight) * old_value) /
	       weight_scale;
}

/* Return the snd_cwnd that was set when the newly acknowledged segment(s) were
 * sent.
 */
static unsigned long get_cwnd(const struct sock *sk)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	//const struct tcp_sock *tp = tcp_sk(sk);

	/* Use the current cwnd initially or if looking for this ack_seq comes up
	 * empty:
	 */
	unsigned long cwnd_old = ca->snd_cwnd;
	//__u32 ack_seq = tp->snd_una;

	if (ca->old_cwnd.cwnd != 0 && ca->old_cwnd.snd_nxt != 0 /*&&
	    before(ca->old_cwnd.snd_nxt, ack_seq)*/) {
		cwnd_old = ca->old_cwnd.cwnd;
	} else {
	}

	return cwnd_old;
}

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
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	/* Not using tcp_int_get_state() here since it uses
	 * BPF_SK_STORAGE_GET_F_CREATE. We might want to use a missing map entry as
	 * an indicator to fall back to RTT-PowerTCP.
	 */
	const struct tcp_int_state *tint =
		bpf_sk_storage_get(&map_tcp_int_state, sk, NULL, 0);

	if (tint) {
		__u32 bandwidth = BITS_TO_BYTES(hop_bw);
		__u32 dt = !prev_int ? tp->srtt_us :
					     (tp->tcp_mstamp - prev_int->hops[0].ts);

		ca->ptcp.cached_int.n_hop = 1;
		/* TCP-INT does not provide an identification for the path. */
		/* TODO: Evaluate if it makes sense to use the switch ID as path ID.
		 * Could lead to a too frequently detected path change, though.
		 */
		ca->ptcp.cached_int.path_id = 1;

		ca->ptcp.cached_int.hops[0].bandwidth = bandwidth;
		ca->ptcp.cached_int.hops[0].qlen = tint->qdepth;
		ca->ptcp.cached_int.hops[0].ts = tp->tcp_mstamp;
		/* In lack of a tx_bytes value, we estimate it here: */
		ca->ptcp.cached_int.hops[0].tx_bytes =
			bandwidth * tint->util / 100 * dt;

		return &ca->ptcp.cached_int;
	} else {
		ca->ptcp.cached_int.n_hop = 0;
	}

	return NULL;
}

static const struct powertcp_int *get_prev_int(struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct powertcp_int *prev_int = &ca->ptcp.prev_int;
	/* With TCP-INT, the difference in tx_bytes since last ACK is already
	 * estimated in get_int(). The previous value must be 0 so
	 * ptcp_norm_power() does not calculate a second difference with a value
	 * potentially coming from a different switch.
	 */
	prev_int->hops[0].tx_bytes = 0;
	return prev_int;
}

/* Return the most recently measured RTT (in us). */
static unsigned long get_rtt(const struct sock *sk,
			     const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	long rtt = rs->rtt_us; /* This is -1 if unavailable. */
	if (rtt < 0) {
		rtt = tp->srtt_us >> 3;
	}
	return rtt;
}

static void require_pacing(struct sock *sk)
{
	/* When using a kernel version before 6.0 that is manually patched with
	 * https://lore.kernel.org/all/20220622191227.898118-2-jthinz@mailbox.tu-berlin.de/,
	 * writing to sk_pacing_* can be enabled with HAVE_WRITABLE_SK_PACING=1
	 * passed to make.
	 */
#if HAVE_WRITABLE_SK_PACING
	bool have_writable_sk_pacing = true;
#else
	bool have_writable_sk_pacing =
		LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 0, 0);
#endif

	if (have_writable_sk_pacing) {
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

static void set_cwnd(struct sock *sk, unsigned long cwnd,
		     struct powertcp_trace_event *trace_event)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long base_bdp = BITS_TO_BYTES(cwnd_scale) * ca->host_bw *
				 ca->base_rtt / tp->mss_cache;

	cwnd = min(cwnd, base_bdp);
	ca->snd_cwnd = cwnd;
	cwnd /= cwnd_scale;
	cwnd = min_t(unsigned long, cwnd, tp->snd_cwnd_clamp);
	tp->snd_cwnd = max(1UL, cwnd);

	if (tracing && trace_event) {
		trace_event->cwnd = tp->snd_cwnd;
	}
}

/* Set the socket pacing rate (bytes per second). */
static void set_rate(struct sock *sk, unsigned long rate)
{
	/* When using a kernel version before 6.0 that is manually patched with
	 * https://lore.kernel.org/all/20220622191227.898118-2-jthinz@mailbox.tu-berlin.de/,
	 * writing to sk_pacing_* can be enabled with HAVE_WRITABLE_SK_PACING=1
	 * passed to make.
	 */
#if HAVE_WRITABLE_SK_PACING
	bool have_writable_sk_pacing = true;
#else
	bool have_writable_sk_pacing =
		LINUX_KERNEL_VERSION >= KERNEL_VERSION(6, 0, 0);
#endif

	if (have_writable_sk_pacing) {
		sk->sk_pacing_rate = min(rate, sk->sk_max_pacing_rate);
	} else {
		/* bpf_setsockopt() only accepts an int for this option: */
		int irate = ~0U;
		bpf_setsockopt(sk, SOL_TCP, SO_MAX_PACING_RATE, &irate,
			       sizeof(irate));
		irate = rate;
		bpf_setsockopt(sk, SOL_TCP, SO_MAX_PACING_RATE, &irate,
			       sizeof(irate));
	}
}

/* Look for the base (~= minimum) RTT (in us). */
static void update_base_rtt(struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 min_rtt;

	if (base_rtt > -1) {
		ca->base_rtt = base_rtt;
		return;
	}

	min_rtt = tcp_min_rtt(tp);
	if (min_rtt != ~0U) {
		ca->base_rtt = min_rtt;
		return;
	}

	min_rtt = tp->srtt_us >> 3;
	if (min_rtt) {
		ca->base_rtt = min_rtt;
		return;
	}

	/* bbr_init_pacing_rate_from_rtt() also uses this as fallback. */
	ca->base_rtt = USEC_PER_SEC;
}

static void update_beta(struct sock *sk, unsigned long old_base_rtt)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (beta < 0 &&
	    (ca->base_rtt < old_base_rtt || old_base_rtt == ULONG_MAX)) {
		unsigned long new_beta =
			BITS_TO_BYTES(cwnd_scale /* * MEGA */ * ca->host_bw *
				      ca->base_rtt / expected_flows) /
			tp->mss_cache /* / USEC_PER_SEC */;
		ca->beta = min(ca->beta, new_beta);
	}
}

static void reset(struct sock *sk, enum tcp_ca_event ev)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long cwnd;
	unsigned long rate;

	if (ev == CA_EVENT_TX_START || ev == CA_EVENT_CWND_RESTART) {
		unsigned long old_base_rtt = ca->base_rtt;
		update_base_rtt(sk);
		update_beta(sk, old_base_rtt);
	}

	/* Only reset those values on a CA_EVENT_CWND_RESTART (used on
	 * initialization). Otherwise we would reset cwnd and rate too frequently if
	 * there are frequent CA_EVENT_TX_STARTs.
	 */
	if (ev == CA_EVENT_CWND_RESTART) {
		rate = BITS_TO_BYTES(MEGA * ca->host_bw);
		set_rate(sk, rate);
		cwnd = cwnd_scale * rate * ca->base_rtt / tp->mss_cache /
		       USEC_PER_SEC;
		set_cwnd(sk, cwnd, NULL);
		tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

		ca->p_smooth = 0;

		clear_old_cwnds(sk);
	}
}

/* Update the list of recent snd_cwnds. */
static bool update_old(struct sock *sk, unsigned long p_smooth)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	__u32 ack_seq = tp->snd_una;
	unsigned long cwnd = ca->snd_cwnd;
	__u32 snd_nxt = tp->snd_nxt;

	if (before(ca->old_cwnd.snd_nxt, ack_seq) ||
	    (ca->old_cwnd.cwnd == 0 && ca->old_cwnd.snd_nxt == 0)) {
		ca->old_cwnd.cwnd = cwnd;
		ca->old_cwnd.snd_nxt = snd_nxt;
	}

	ca->p_smooth = p_smooth;

	return true;
}

static unsigned long update_window(struct sock *sk, unsigned long cwnd_old,
				   unsigned long norm_power,
				   struct powertcp_trace_event *trace_event)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	unsigned long cwnd;

	norm_power = max(norm_power, 1UL);
	cwnd = ewma(gamma, gamma_scale,
		    power_scale * cwnd_old / norm_power + ca->beta,
		    ca->snd_cwnd);
	cwnd = max(1UL, cwnd);
	set_cwnd(sk, cwnd, trace_event);
	return cwnd;
}

static unsigned long ptcp_norm_power(struct sock *sk,
				     const struct rate_sample *rs,
				     struct powertcp_trace_event *trace_event)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	unsigned long delta_t = 0;
	unsigned long p_norm = 0;
	unsigned long p_smooth = ca->p_smooth;

	const struct powertcp_int *prev_int = get_prev_int(sk);
	const struct powertcp_int *this_int = get_int(sk, prev_int);
	int i;

	/* TODO: Do something helpful (a full reset?) when the path changes. */
	if (!this_int || !prev_int || this_int->path_id != prev_int->path_id) {
		return p_smooth > 0 ? p_smooth : power_scale;
	}

	/* for each egress port i on the path */
	for (i = 0; i < this_int->n_hop && i < max_n_hops; ++i) {
		const struct powertcp_hop_int *hop_int = &this_int->hops[i];
		const struct powertcp_hop_int *prev_hop_int =
			&prev_int->hops[i];
		unsigned long dt = max(hop_int->ts - prev_hop_int->ts, 1u);
		long queue_diff =
			hop_int->qlen > 0 ?
				      (long)hop_int->qlen - (long)prev_hop_int->qlen :
				      0;
		long tx_bytes_diff =
			(long)hop_int->tx_bytes - (long)prev_hop_int->tx_bytes;
		/* The variable name "current" instead of lambda would conflict with a
		 * macro of the same name in asm-generic/current.h.
		 */
		unsigned long lambda = max(1l, queue_diff + tx_bytes_diff) *
				       (USEC_PER_SEC / dt);
		unsigned long bdp = hop_int->bandwidth * ca->base_rtt;
		unsigned long voltage = hop_int->qlen + bdp;
		unsigned long hop_p = lambda * voltage;
		unsigned long equilibrium = max(
			(unsigned long)hop_int->bandwidth * hop_int->bandwidth /
				power_scale * MEGA * ca->base_rtt,
			1ul);
		unsigned long hop_p_norm = hop_p / equilibrium;
		if (hop_p_norm > p_norm) {
			p_norm = hop_p_norm;
			delta_t = dt;

			if (tracing && trace_event) {
				trace_event->time =
					bpf_ktime_get_ns() / NSEC_PER_USEC;
				trace_event->qlen = hop_int->qlen;
			}
		}
	}

	delta_t = min(delta_t, ca->base_rtt);
	p_smooth = p_smooth == 0 ?
				 p_norm :
				 ewma(delta_t, ca->base_rtt, p_norm, p_smooth);

	if (tracing && trace_event) {
		trace_event->p_norm = p_smooth;
	}

	return p_smooth;
}

static void ptcp_reset(struct sock *sk, enum tcp_ca_event ev)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct powertcp_int *prev_int = &ca->ptcp.prev_int;
	prev_int->path_id = 0;

	reset(sk, ev);
}

static bool ptcp_update_old(struct sock *sk, const struct rate_sample *rs,
			    unsigned long p_smooth)
{
	struct powertcp *ca = inet_csk_ca(sk);

	ca->ptcp.prev_int = ca->ptcp.cached_int;

	return update_old(sk, p_smooth);
}

static unsigned long
ptcp_update_window(struct sock *sk, unsigned long cwnd_old,
		   unsigned long norm_power,
		   struct powertcp_trace_event *trace_event)
{
	return update_window(sk, cwnd_old, norm_power, trace_event);
}

static unsigned long
rttptcp_norm_power(const struct sock *sk, const struct rate_sample *rs,
		   struct powertcp_trace_event *trace_event)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned long dt, rtt_grad, p_norm, delta_t;
	unsigned long p_smooth = ca->p_smooth;
	unsigned long rtt_us;

	if (before(tp->snd_una, ca->rttptcp.last_updated)) {
		return p_smooth > 0 ? p_smooth : power_scale;
	}

	rtt_us = get_rtt(sk, rs);
	/* Timestamps are always increasing here, logically. So we want to have
	 * unsigned wrap-around when it's time and don't use tcp_stamp_us_delta().
	 */
	dt = tp->tcp_mstamp - ca->rttptcp.t_prev;
	dt = max(dt, 1UL);
	delta_t = min(dt, ca->base_rtt);
	/* Limiting rtt_grad to non-negative values. */
	rtt_grad = power_scale *
		   (rtt_us - min(ca->rttptcp.prev_rtt_us, rtt_us)) / dt;
	p_norm = (rtt_grad + power_scale) * rtt_us / ca->base_rtt;
	/* powertcp.p_smooth is initialized with 0, we don't want to smooth for the
	 * very first calculation.
	 */
	p_smooth = p_smooth == 0 ?
				 p_norm :
				 ewma(delta_t, ca->base_rtt, p_norm, p_smooth);

	if (tracing && trace_event) {
		trace_event->p_norm = p_smooth;
		trace_event->time = bpf_ktime_get_ns() / NSEC_PER_USEC;
	}

	return p_smooth;
}

static void rttptcp_reset(struct sock *sk, enum tcp_ca_event ev)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	reset(sk, ev);

	/* Only reset those on initialization. */
	if (ev == CA_EVENT_CWND_RESTART) {
		// TODO: Evaluate if it actually improves performance of the algorithm
		// to reset those two values only on CA_EVENT_CWND_RESTART:
		ca->rttptcp.last_updated = tp->snd_nxt;
		ca->rttptcp.prev_rtt_us = tp->srtt_us >> 3;
	}

	ca->rttptcp.t_prev = tp->tcp_mstamp;
}

static bool rttptcp_update_old(struct sock *sk, const struct rate_sample *rs,
			       unsigned long p_smooth)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (before(tp->snd_una, ca->rttptcp.last_updated)) {
		return false;
	}

	update_old(sk, p_smooth);

	ca->rttptcp.last_updated = tp->snd_nxt;
	ca->rttptcp.prev_rtt_us = get_rtt(sk, rs);
	// TODO: There are multiple timestamps available here. Is there a better one?
	ca->rttptcp.t_prev = tp->tcp_mstamp;

	return true;
}

static unsigned long
rttptcp_update_window(struct sock *sk, unsigned long cwnd_old,
		      unsigned long norm_power,
		      struct powertcp_trace_event *trace_event)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (before(tp->snd_una, ca->rttptcp.last_updated)) {
		return ca->snd_cwnd;
	}

	return update_window(sk, cwnd_old, norm_power, trace_event);
}

#define DEFINE_POWERTCP_VARIANT(func_prefix, cong_ops_name)                    \
	SEC("struct_ops/powertcp_##func_prefix##_cwnd_event")                  \
	void BPF_PROG(powertcp_##func_prefix##_cwnd_event, struct sock *sk,    \
		      enum tcp_ca_event ev)                                    \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
                                                                               \
		if (ca->host_bw == 0) {                                        \
			return;                                                \
		}                                                              \
                                                                               \
		if (ev == CA_EVENT_TX_START) {                                 \
			func_prefix##_reset(sk, ev);                           \
		}                                                              \
	}                                                                      \
                                                                               \
	SEC("struct_ops/powertcp_##func_prefix##_init")                        \
	void BPF_PROG(powertcp_##func_prefix##_init, struct sock *sk)          \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
                                                                               \
		BUILD_BUG_ON(sizeof(struct powertcp) >                         \
			     sizeof(((struct inet_connection_sock *)NULL)      \
					    ->icsk_ca_priv));                  \
                                                                               \
		ca->base_rtt = ULONG_MAX;                                      \
		ca->beta = beta < 0 ? ULONG_MAX : beta;                        \
		ca->host_bw = get_host_bw(sk);                                 \
                                                                               \
		func_prefix##_reset(sk, CA_EVENT_CWND_RESTART);                \
                                                                               \
		require_pacing(sk);                                            \
	}                                                                      \
                                                                               \
	SEC("struct_ops/powertcp_##func_prefix##_cong_control")                \
	void BPF_PROG(powertcp_##func_prefix##_cong_control, struct sock *sk,  \
		      const struct rate_sample *rs)                            \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
		const struct tcp_sock *tp = tcp_sk(sk);                        \
		unsigned long cwnd_old;                                        \
		unsigned long norm_power;                                      \
		unsigned long cwnd;                                            \
		unsigned long rate;                                            \
		struct powertcp_trace_event trace_event = {};                  \
                                                                               \
		if (ca->host_bw == 0) {                                        \
			return;                                                \
		}                                                              \
                                                                               \
		cwnd_old = get_cwnd(sk);                                       \
		norm_power = func_prefix##_norm_power(sk, rs, &trace_event);   \
		cwnd = func_prefix##_update_window(sk, cwnd_old, norm_power,   \
						   &trace_event);              \
		rate = (USEC_PER_SEC * cwnd * tp->mss_cache) / ca->base_rtt /  \
		       cwnd_scale;                                             \
		set_rate(sk, rate);                                            \
		func_prefix##_update_old(sk, rs, norm_power);                  \
                                                                               \
		if (tracing && trace_event.time != 0) {                        \
			trace_event.rate = rate;                               \
			trace_event.sk_hash = sk->__sk_common.skc_hash;        \
			bpf_ringbuf_output(&trace_events, &trace_event,        \
					   sizeof(trace_event), 0);            \
		}                                                              \
	}                                                                      \
                                                                               \
	SEC(".struct_ops")                                                     \
	struct tcp_congestion_ops cong_ops_name = {                            \
		.cong_avoid = (void *)powertcp_cong_avoid,                     \
		.cong_control = (void *)powertcp_##func_prefix##_cong_control, \
		.cwnd_event = (void *)powertcp_##func_prefix##_cwnd_event,     \
		.init = (void *)powertcp_##func_prefix##_init,                 \
		.name = "bpf_" #cong_ops_name,                                 \
		.release = (void *)powertcp_release,                           \
		.ssthresh = (void *)powertcp_ssthresh,                         \
		.undo_cwnd = (void *)powertcp_undo_cwnd,                       \
	}

SEC("struct_ops/powertcp_cong_avoid")
void BPF_PROG(powertcp_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
	/* Before, tcp_congestion_ops.cong_avoid was non-optional in
	 * net/ipv4/bpf_tcp_ca.c, even if it is never used when cong_control is
	 * also set. This was fixed in Linux 6.0 with
	 * https://lore.kernel.org/all/20220622191227.898118-3-jthinz@mailbox.tu-berlin.de/.
	 *
	 * This stub is kept here for compatibility with older kernels.
	 */
}

SEC("struct_ops/powertcp_release")
void BPF_PROG(powertcp_release, struct sock *sk)
{
	/* TODO: The release function could be dropped since it does not free
	 * anything in the eBPF version. But we keep it for now.
	 */
	const struct powertcp *ca = inet_csk_ca(sk);

	if (ca->host_bw == 0) {
		return;
	}

	clear_old_cwnds(sk);
}

SEC("struct_ops/powertcp_ssthresh")
__u32 BPF_PROG(powertcp_ssthresh, struct sock *sk)
{
	/* We don't do slow starts here! */
	return TCP_INFINITE_SSTHRESH;
}

SEC("struct_ops/powertcp_undo_cwnd")
__u32 BPF_PROG(powertcp_undo_cwnd, struct sock *sk)
{
	/* Never undo after a loss. */
	return tcp_sk(sk)->snd_cwnd;
}

DEFINE_POWERTCP_VARIANT(ptcp, powertcp);

/* Cannot name it rtt_powertcp due to the size limit for
 * tcp_congestion_ops.name. */
DEFINE_POWERTCP_VARIANT(rttptcp, rttpowertcp);
