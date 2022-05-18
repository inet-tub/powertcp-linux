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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "Dual MIT/GPL";

#define INT_MAX 2147483647
#define MEGA 1000000UL
#define TCP_INFINITE_SSTHRESH 0x7fffffff
#define USEC_PER_SEC 1000000L

struct old_cwnd {
	__u32 snd_nxt;
	__u32 cwnd;
};

struct powertcp {
	// TODO: Sort members in a cache-friendly way if necessary.

	struct {
		__u32 last_updated;
		long prev_rtt_us;
		__u64 t_prev;
	} rttptcp;

	int beta;

	struct old_cwnd old_cwnd;

	long p_smooth;

	/* powertcp_cong_control() seems to (unexpectedly) get called once before
	 * powertcp_init(). host_bw is still 0 then, thanks to
	 * tcp_assign_congestion_control(), and we use that as an indicator whether
	 * we are initialized.
	 */
	unsigned long host_bw; /* Mbit/s */
};

const long beta_scale = (1L << 10);
const unsigned long fallback_host_bw = 1000; /* Mbit/s */
const long gamma_scale = (1L << 10);
const long power_scale = (1L << 16);

int base_rtt = -1;
int beta = -1;
int expected_flows = 10;
int gamma = 0.9 * gamma_scale;

/* NOTE: Would need to reimplement some of those (mostly trivial) functions and
 * macros ourselves, when using vmlinux.h instead of bpf_tcp_helpers.h. Have to
 * see if that's worth it ("it" means using the generated vmlinux.h instead of
 * requiring unpacked Linux sources for access to bpf_tcp_helpers.h).
 */
#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))
#define BITS_PER_BYTE 8
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_BYTES(nr) __KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(char))
#define BUILD_BUG_ON(cond)                                                     \
	if (cond) {                                                            \
		__bpf_unreachable();                                           \
	}
#define max(x, y) (((x) > (y)) ? (x) : (y))
#define max_t(type, x, y) max((type)(x), (type)(y))
#define min(x, y) (((x) < (y)) ? (x) : (y))
#define min_t(type, x, y) min((type)(x), (type)(y))

static inline bool before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1 - seq2) < 0;
}
#define after(seq2, seq1) before(seq1, seq2)

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

/* Minimum RTT in usec. ~0 means not available. */
static inline __u32 tcp_min_rtt(const struct tcp_sock *tp)
{
	return tp->rtt_min.s[0].v;
}

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

static inline __u32 tcp_stamp_us_delta(__u64 t1, __u64 t0)
{
	return max_t(__s64, t1 - t0, 0);
}

/* Look for the base (~= minimum) RTT (in us). */
static long get_base_rtt(const struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	__u32 min_rtt;

	if (base_rtt > -1) {
		return base_rtt;
	}

	min_rtt = tcp_min_rtt(tp);
	if (min_rtt != ~0U) {
		return min_rtt;
	}

	if (rs && rs->rtt_us != -1L) {
		return rs->rtt_us;
	}

	/* bbr_init_pacing_rate_from_rtt() also uses this as fallback. */
	return USEC_PER_SEC;
}

static void clear_old_cwnds(struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);
	ca->old_cwnd.cwnd = 0;
	ca->old_cwnd.snd_nxt = 0;
}

/* Return the snd_cwnd that was set when the newly acknowledged segment(s) were
 * sent.
 */
static __u32 get_cwnd(const struct sock *sk)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Use the current cwnd initially or if looking for this ack_seq comes up
	 * empty:
	 */
	__u32 cwnd_old = tp->snd_cwnd;
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
	return fallback_host_bw;
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

/* Return the most recently measured RTT (in us). */
static long get_rtt(const struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	long rtt = rs->rtt_us; /* This is -1 if unavailable. */
	if (rtt < 0) {
		rtt = tp->srtt_us >> 3;
	}
	return rtt;
}

static void set_cwnd(struct tcp_sock *tp, __u32 cwnd)
{
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
}

/* Set the socket pacing rate (bytes per second). */
static void set_rate(struct sock *sk, unsigned long rate)
{
#if HAVE_WRITABLE_SK_PACING
	/* TODO: May have to patch the kernel to be able to set sk_pacing_rate from
	 * a BPF TCP CC. */
	sk->sk_pacing_rate = min(rate, sk->sk_max_pacing_rate);
#endif
}

static void reset(struct sock *sk, enum tcp_ca_event ev, long base_rtt_us)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 cwnd;
	unsigned long rate;

	/* Only reset those values on a CA_EVENT_CWND_RESTART (used on
	 * initialization). Otherwise we would reset cwnd and rate too frequently if
	 * there are frequent CA_EVENT_TX_STARTs.
	 */
	if (ev == CA_EVENT_CWND_RESTART) {
		if (base_rtt_us == -1L) {
			base_rtt_us = get_base_rtt(sk, NULL);
		}

		rate = BITS_TO_BYTES(MEGA * ca->host_bw);
		set_rate(sk, rate);
		cwnd = rate * base_rtt_us / tp->mss_cache / USEC_PER_SEC;
		set_cwnd(tp, cwnd);
		tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

		ca->p_smooth = -1;

		clear_old_cwnds(sk);
	}
}

static long smooth_power(long p_smooth, long p_norm, long base_rtt_us,
			 long delta_t)
{
	/* powertcp.p_smooth is initialized with -1, we don't want to smooth for the
	 * very first calculation.
	 */
	return p_smooth < 0 ? p_norm :
				    (p_smooth * (base_rtt_us - delta_t) +
			       (p_norm * delta_t)) /
				      (unsigned long)base_rtt_us;
}

static void update_beta(struct sock *sk, long base_rtt_us)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (beta < 0) {
		/* We are actually looking whether the base RTT got smaller, but don't
		 * want to remember that in a separate variable in struct powertcp.
		 * Space is precious in there. All values besides the base RTT and,
		 * rarely, the MSS do not change at runtime in the calculation of beta.
		 */
		int new_beta =
			BITS_TO_BYTES(beta_scale /* * MEGA */ * ca->host_bw *
				      base_rtt_us / expected_flows) /
			tp->mss_cache /* / USEC_PER_SEC */;
		ca->beta = min(ca->beta, new_beta);
	}
}

/* Update the list of recent snd_cwnds. */
static bool update_old(struct sock *sk, long p_smooth)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	__u32 ack_seq = tp->snd_una;
	__u32 cwnd = tp->snd_cwnd;
	__u32 snd_nxt = tp->snd_nxt;

	if (before(ca->old_cwnd.snd_nxt, ack_seq) ||
	    (ca->old_cwnd.cwnd == 0 && ca->old_cwnd.snd_nxt == 0)) {
		ca->old_cwnd.cwnd = cwnd;
		ca->old_cwnd.snd_nxt = snd_nxt;
	}

	ca->p_smooth = p_smooth;

	return true;
}

static __u32 update_window(struct sock *sk, __u32 cwnd_old, long norm_power)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 cwnd;

	norm_power = max(norm_power, 1L);
	cwnd = ((gamma *
		 (beta_scale * power_scale * cwnd_old / norm_power + ca->beta) /
		 beta_scale) +
		(gamma_scale - gamma) * tp->snd_cwnd) /
	       gamma_scale;
	cwnd = max(1U, cwnd);
	set_cwnd(tp, cwnd);
	return cwnd;
}

static long rttptcp_norm_power(const struct sock *sk,
			       const struct rate_sample *rs, long base_rtt_us)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	long dt, rtt_grad, p_norm, delta_t;
	long p_smooth = ca->p_smooth;
	long rtt_us;

	if (before(tp->snd_una, ca->rttptcp.last_updated)) {
		return p_smooth > -1 ? p_smooth : power_scale;
	}

	rtt_us = get_rtt(sk, rs);
	dt = max_t(long, 1L,
		   tcp_stamp_us_delta(tp->tcp_mstamp, ca->rttptcp.t_prev));
	delta_t = min(dt, base_rtt_us);
	rtt_grad = max(power_scale * (rtt_us - ca->rttptcp.prev_rtt_us) /
			       (unsigned long)dt,
		       0UL);
	p_norm = (rtt_grad + power_scale) * rtt_us / (unsigned long)base_rtt_us;
	p_smooth = smooth_power(p_smooth, p_norm, base_rtt_us, delta_t);

	return p_smooth;
}

static void rttptcp_reset(struct sock *sk, enum tcp_ca_event ev,
			  long base_rtt_us)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (base_rtt_us == -1L) {
		base_rtt_us = get_base_rtt(sk, NULL);
	}

	/* Only reset those on initialization. */
	if (ev == CA_EVENT_CWND_RESTART) {
		// TODO: Evaluate if it actually improves performance of the algorithm
		// to reset those two values only on CA_EVENT_CWND_RESTART:
		ca->rttptcp.last_updated = tp->snd_nxt;
		ca->rttptcp.prev_rtt_us = tp->srtt_us >> 3;
	}

	ca->rttptcp.t_prev = tp->tcp_mstamp;

	reset(sk, ev, base_rtt_us);
}

static bool rttptcp_update_old(struct sock *sk, const struct rate_sample *rs,
			       long p_smooth)
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

static __u32 rttptcp_update_window(struct sock *sk, __u32 cwnd_old,
				   long norm_power)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (before(tp->snd_una, ca->rttptcp.last_updated)) {
		return tp->snd_cwnd;
	}

	return update_window(sk, cwnd_old, norm_power);
}

SEC("struct_ops/powertcp_cwnd_event")
void BPF_PROG(powertcp_cwnd_event, struct sock *sk, enum tcp_ca_event ev)
{
	struct powertcp *ca = inet_csk_ca(sk);

	if (ca->host_bw == 0) {
		return;
	}

	if (ev == CA_EVENT_TX_START) {
		rttptcp_reset(sk, ev, -1);
	}
}

SEC("struct_ops/powertcp_init")
void BPF_PROG(powertcp_init, struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);

	BUILD_BUG_ON(
		sizeof(struct powertcp) >
		sizeof(((struct inet_connection_sock *)NULL)->icsk_ca_priv));

	if (beta < 0) {
		ca->beta = INT_MAX;
	} else {
		ca->beta = beta;
	}
	ca->host_bw = get_host_bw(sk);

	rttptcp_reset(sk, CA_EVENT_CWND_RESTART, -1);

#if HAVE_WRITABLE_SK_PACING
	/* TODO: May have to patch the kernel to be able to set sk_pacing_status from
	 * a BPF TCP CC. */
	/* We do want sk_pacing_rate to be respected: */
	//cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
	if (sk->sk_pacing_status == SK_PACING_NONE) {
		sk->sk_pacing_status = SK_PACING_NEEDED;
	}
#endif
}

SEC("struct_ops/powertcp_cong_avoid")
void BPF_PROG(powertcp_cong_avoid, struct sock *sk, __u32 ack, __u32 acked)
{
	/* tcp_congestion_ops.cong_avoid is unfortunately non-optional in
	 * net/ipv4/bpf_tcp_ca.c, even if it is never used when cong_control is
	 * also set. This might be an oversight.
	 */
}

SEC("struct_ops/powertcp_cong_control")
void BPF_PROG(powertcp_cong_control, struct sock *sk,
	      const struct rate_sample *rs)
{
	/* cong_control, if assigned in tcp_congestion_ops, becomes the main
	 * congestion control function and is responsible for setting cwnd and rate.
	*/

	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	__u32 cwnd_old;
	long norm_power;
	__u32 cwnd;
	unsigned long rate;
	long base_rtt_us;

	if (ca->host_bw == 0) {
		return;
	}

	base_rtt_us = get_base_rtt(sk, rs);
	update_beta(sk, base_rtt_us);

	cwnd_old = get_cwnd(sk);
	norm_power = rttptcp_norm_power(sk, rs, base_rtt_us);
	cwnd = rttptcp_update_window(sk, cwnd_old, norm_power);
	rate = (USEC_PER_SEC * cwnd * tp->mss_cache) /
	       (unsigned long)base_rtt_us;
	set_rate(sk, rate);
	rttptcp_update_old(sk, rs, norm_power);
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
	// TODO: Or do we?
	return tcp_sk(sk)->snd_cwnd;
}

SEC(".struct_ops")
struct tcp_congestion_ops rtt_powertcp = {
	.cong_avoid = (void *)powertcp_cong_avoid,
	.cong_control = (void *)powertcp_cong_control,
	.cwnd_event = (void *)powertcp_cwnd_event,
	.init = (void *)powertcp_init,
	/* Cannot name it bpf_rtt_powertcp due to the size limit for .name. */
	.name = "bpf_rttpowertcp",
	.release = (void *)powertcp_release,
	.ssthresh = (void *)powertcp_ssthresh,
	.undo_cwnd = (void *)powertcp_undo_cwnd,
};
