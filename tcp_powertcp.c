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

#include "tcp_powertcp.h"

#include <linux/ethtool.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <net/tcp.h>

#define CREATE_TRACE_POINTS
#include "tcp_powertcp_trace.h"

#define MEGA 1000000UL

struct old_cwnd {
	u32 snd_nxt;
	unsigned long cwnd;
	struct list_head list;
};

enum { max_n_hops = 1 };

struct powertcp_hop_int {
	u32 bandwidth;
	u32 ts;
	u32 tx_bytes;
	u32 qlen;
};

struct powertcp_int {
	int n_hop;
	int path_id;
	struct powertcp_hop_int hops[max_n_hops];
};

static int base_rtt __read_mostly = -1;
static int beta __read_mostly = -1;
static int expected_flows __read_mostly = 10;
static int gamma __read_mostly = 0.9 * gamma_scale;

module_param(base_rtt, int, 0444);
MODULE_PARM_DESC(
	base_rtt,
	"base (minimum) round-trip time (RTT) in us (default: -1; -1: automatically detect)");
module_param(beta, int, 0444);
MODULE_PARM_DESC(beta,
		 "additive increase (default: -1; -1: automatically set beta)");
module_param(expected_flows, int, 0444);
MODULE_PARM_DESC(expected_flows,
		 "expected number of flows sharing the host NIC (default: 10)");
module_param(gamma, int, 0444);
MODULE_PARM_DESC(gamma, "exponential moving average weight, times " __stringify(
				gamma_scale) "(default: 921 ~= 0,9)");

/* Look for the base (~= minimum) RTT (in us). */
static unsigned long get_base_rtt(const struct sock *sk,
				  const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 min_rtt;

	if (base_rtt > -1) {
		return base_rtt;
	}

	min_rtt = tcp_min_rtt(tp);
	if (likely(min_rtt != ~0U)) {
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
	struct old_cwnd *old_cwnd;
	struct old_cwnd *tmp;
	list_for_each_entry_safe (old_cwnd, tmp, &ca->old_cwnds, list) {
		list_del(&old_cwnd->list);
		kfree(old_cwnd);
	}
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
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Use the current cwnd initially or if looking for this ack_seq comes up
	 * empty:
	 */
	unsigned long cwnd_old = ca->snd_cwnd;
	u32 ack_seq = tp->snd_una;

	struct old_cwnd *old_cwnd;
	list_for_each_entry (old_cwnd, &ca->old_cwnds, list) {
		if (!before(old_cwnd->snd_nxt, ack_seq)) {
			break;
		}
		cwnd_old = old_cwnd->cwnd;
	}

	return cwnd_old;
}

/* Look for the host bandwidth (in Mbit/s). */
static unsigned long get_host_bw(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
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
}

static const struct powertcp_int *get_int(struct sock *sk,
					  const struct powertcp_int *prev_int)
{
	return NULL;
}

static const struct powertcp_int *get_prev_int(struct sock *sk)
{
	return NULL;
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

static void set_cwnd(struct sock *sk, unsigned long cwnd)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	ca->snd_cwnd = cwnd;
	cwnd /= cwnd_scale;
	cwnd = min_t(unsigned long, cwnd, tp->snd_cwnd_clamp);
	tp->snd_cwnd = max(1UL, cwnd);
}

/* Set the socket pacing rate (bytes per second). */
static void set_rate(struct sock *sk, unsigned long rate)
{
	sk->sk_pacing_rate = min(rate, sk->sk_max_pacing_rate);
}

static void reset(struct sock *sk, enum tcp_ca_event ev,
		  unsigned long base_rtt_us)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned long cwnd;
	unsigned long rate;

	/* Only reset those values on a CA_EVENT_CWND_RESTART (used on
	 * initialization). Otherwise we would reset cwnd and rate too frequently if
	 * there are frequent CA_EVENT_TX_STARTs.
	 */
	if (ev == CA_EVENT_CWND_RESTART) {
		if (base_rtt_us == 0) {
			base_rtt_us = get_base_rtt(sk, NULL);
		}

		rate = BITS_TO_BYTES(MEGA * ca->host_bw);
		set_rate(sk, rate);
		cwnd = cwnd_scale * rate * base_rtt_us / tp->mss_cache /
		       USEC_PER_SEC;
		set_cwnd(sk, cwnd);
		tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

		ca->p_smooth = 0;

		clear_old_cwnds(sk);
	}

	trace_reset(tp->tcp_mstamp, sk->sk_hash, ev, base_rtt_us, ca->snd_cwnd,
		    sk->sk_pacing_rate);
}

static void update_beta(struct sock *sk, unsigned long base_rtt_us)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (beta < 0) {
		/* We are actually looking whether the base RTT got smaller, but don't
		 * want to remember that in a separate variable in struct powertcp.
		 * Space is precious in there. All values besides the base RTT and,
		 * rarely, the MSS do not change at runtime in the calculation of beta.
		 */
		unsigned long new_beta =
			BITS_TO_BYTES(cwnd_scale /* * MEGA */ * ca->host_bw *
				      base_rtt_us / expected_flows) /
			tp->mss_cache /* / USEC_PER_SEC */;
		ca->beta = min(ca->beta, new_beta);
	}
}

/* Update the list of recent snd_cwnds. */
static bool update_old(struct sock *sk, unsigned long p_smooth)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	u32 ack_seq = tp->snd_una;
	unsigned long cwnd = ca->snd_cwnd;
	u32 snd_nxt = tp->snd_nxt;

	struct old_cwnd *n;
	struct old_cwnd *to_del = NULL;

	/* Remember the current snd_cwnd if snd_nxt did advance. Update the already
	 * remembered snd_cwnd for this snd_nxt otherwise (assuming snd_nxt does
	 * never *decrease* logically).
	 */
	struct old_cwnd *old_cwnd =
		!list_empty(&ca->old_cwnds) ?
			      list_last_entry(&ca->old_cwnds, struct old_cwnd, list) :
			      NULL;
	if (!old_cwnd || before(old_cwnd->snd_nxt, snd_nxt)) {
		old_cwnd = kmalloc(sizeof(*old_cwnd), GFP_KERNEL);
		if (old_cwnd) {
			list_add_tail(&old_cwnd->list, &ca->old_cwnds);
		}
	}

	if (old_cwnd) {
		old_cwnd->snd_nxt = snd_nxt;
		old_cwnd->cwnd = cwnd;
	}

	/* Drop old snd_cwnds whos snd_nxt is strictly before the new ack_seq,
	 * meaning they have been used in a transmission.
	 */
	list_for_each_entry_safe (old_cwnd, n, &ca->old_cwnds, list) {
		if (!before(old_cwnd->snd_nxt, ack_seq)) {
			break;
		}
		if (to_del) {
			list_del(&to_del->list);
			kfree(to_del);
		}
		to_del = old_cwnd;
	}

	ca->p_smooth = p_smooth;

	return true;
}

static unsigned long update_window(struct sock *sk, unsigned long cwnd_old,
				   unsigned long norm_power)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	unsigned long cwnd;

	norm_power = max(norm_power, 1UL);
	cwnd = ewma(gamma, gamma_scale,
		    power_scale * cwnd_old / norm_power + ca->beta,
		    ca->snd_cwnd);
	cwnd = max(1UL, cwnd);
	trace_update_window(sk, cwnd_old, norm_power, cwnd);
	set_cwnd(sk, cwnd);
	return cwnd;
}

static unsigned long ptcp_norm_power(struct sock *sk,
				     const struct rate_sample *rs,
				     unsigned long base_rtt_us)
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
		unsigned long queue_grad =
			hop_int->qlen > prev_hop_int->qlen ?
				      power_scale * USEC_PER_SEC *
					(hop_int->qlen - prev_hop_int->qlen) /
					dt :
				      0;
		unsigned long rate =
			power_scale * USEC_PER_SEC *
			(hop_int->tx_bytes - prev_hop_int->tx_bytes) / dt;
		/* The variable name "current" instead of lambda would conflict with a
		 * macro of the same name in asm-generic/current.h.
		 */
		unsigned long lambda = max(1ul, queue_grad + rate);
		unsigned long bdp =
			hop_int->bandwidth * base_rtt_us / USEC_PER_SEC;
		unsigned long voltage = hop_int->qlen + bdp;
		unsigned long hop_p = lambda * voltage;
		/* NOTE: equilibrium will overflow for switches with above-100 GBit/s
		 * interfaces:
		 */
		unsigned long equilibrium =
			max(hop_int->bandwidth / USEC_PER_SEC *
				    hop_int->bandwidth * base_rtt_us,
			    1ul);
		unsigned long hop_p_norm = hop_p / equilibrium;
		if (hop_p_norm > p_norm) {
			p_norm = hop_p_norm;
			delta_t = dt;
		}
	}

	delta_t = min(delta_t, base_rtt_us);
	p_smooth = p_smooth == 0 ? p_norm :
					 ewma(delta_t, base_rtt_us, p_norm, p_smooth);

	return p_smooth;
}

static void ptcp_reset(struct sock *sk, enum tcp_ca_event ev,
		       unsigned long base_rtt_us)
{
	/* TODO: Anything special to do here for this variant? */
	reset(sk, ev, base_rtt_us);
}

static bool ptcp_update_old(struct sock *sk, const struct rate_sample *rs,
			    unsigned long p_smooth)
{
	/* TODO: Remember INT data for next calculation. */

	return update_old(sk, p_smooth);
}

static unsigned long ptcp_update_window(struct sock *sk, unsigned long cwnd_old,
					unsigned long norm_power)
{
	return update_window(sk, cwnd_old, norm_power);
}

static unsigned long rttptcp_norm_power(const struct sock *sk,
					const struct rate_sample *rs,
					unsigned long base_rtt_us)
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
	delta_t = min(dt, base_rtt_us);
	/* Limiting rtt_grad to non-negative values. */
	rtt_grad = power_scale *
		   (rtt_us - min(ca->rttptcp.prev_rtt_us, rtt_us)) / dt;
	p_norm = (rtt_grad + power_scale) * rtt_us / base_rtt_us;
	/* powertcp.p_smooth is initialized with 0, we don't want to smooth for the
	 * very first calculation.
	 */
	p_smooth = p_smooth == 0 ? p_norm :
					 ewma(delta_t, base_rtt_us, p_norm, p_smooth);

	trace_norm_power(sk, dt, delta_t, rtt_us, rtt_grad, base_rtt_us, p_norm,
			 p_smooth);

	return p_smooth;
}

static void rttptcp_reset(struct sock *sk, enum tcp_ca_event ev,
			  unsigned long base_rtt_us)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (base_rtt_us == 0) {
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

static unsigned long rttptcp_update_window(struct sock *sk,
					   unsigned long cwnd_old,
					   unsigned long norm_power)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (before(tp->snd_una, ca->rttptcp.last_updated)) {
		return ca->snd_cwnd;
	}

	return update_window(sk, cwnd_old, norm_power);
}

#define DEFINE_POWERTCP_VARIANT(func_prefix, cong_ops_name)                    \
	void powertcp_##func_prefix##_cwnd_event(struct sock *sk,              \
						 enum tcp_ca_event ev)         \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
                                                                               \
		if (unlikely(ca->host_bw == 0)) {                              \
			return;                                                \
		}                                                              \
                                                                               \
		if (ev == CA_EVENT_TX_START) {                                 \
			func_prefix##_reset(sk, ev, 0);                        \
		}                                                              \
	}                                                                      \
                                                                               \
	void powertcp_##func_prefix##_init(struct sock *sk)                    \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
                                                                               \
		memset(&ca->func_prefix, 0, sizeof(ca->func_prefix));          \
                                                                               \
		if (beta < 0) {                                                \
			ca->beta = ULONG_MAX;                                  \
		} else {                                                       \
			ca->beta = beta;                                       \
		}                                                              \
		ca->host_bw = get_host_bw(sk);                                 \
		INIT_LIST_HEAD(&ca->old_cwnds);                                \
                                                                               \
		func_prefix##_reset(sk, CA_EVENT_CWND_RESTART, 0);             \
                                                                               \
		/* We do want sk_pacing_rate to be respected: */               \
		cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE,                 \
			SK_PACING_NEEDED);                                     \
	}                                                                      \
                                                                               \
	void powertcp_##func_prefix##_cong_control(                            \
		struct sock *sk, const struct rate_sample *rs)                 \
	{                                                                      \
		struct powertcp *ca = inet_csk_ca(sk);                         \
		const struct tcp_sock *tp = tcp_sk(sk);                        \
		unsigned long cwnd_old;                                        \
		unsigned long norm_power;                                      \
		unsigned long cwnd;                                            \
		unsigned long rate;                                            \
		unsigned long base_rtt_us;                                     \
                                                                               \
		if (unlikely(ca->host_bw == 0)) {                              \
			return;                                                \
		}                                                              \
                                                                               \
		base_rtt_us = get_base_rtt(sk, rs);                            \
		update_beta(sk, base_rtt_us);                                  \
                                                                               \
		cwnd_old = get_cwnd(sk);                                       \
		norm_power = func_prefix##_norm_power(sk, rs, base_rtt_us);    \
		cwnd = func_prefix##_update_window(sk, cwnd_old, norm_power);  \
		rate = (USEC_PER_SEC * cwnd * tp->mss_cache) / base_rtt_us /   \
		       cwnd_scale;                                             \
		set_rate(sk, rate);                                            \
		func_prefix##_update_old(sk, rs, norm_power);                  \
	}                                                                      \
                                                                               \
	static struct tcp_congestion_ops cong_ops_name __read_mostly = {       \
		.cong_control = powertcp_##func_prefix##_cong_control,         \
		.cwnd_event = powertcp_##func_prefix##_cwnd_event,             \
		.init = powertcp_##func_prefix##_init,                         \
		.name = #cong_ops_name,                                        \
		.owner = THIS_MODULE,                                          \
		.release = powertcp_release,                                   \
		.ssthresh = powertcp_ssthresh,                                 \
		.undo_cwnd = powertcp_undo_cwnd,                               \
	}

static void powertcp_release(struct sock *sk)
{
	const struct powertcp *ca = inet_csk_ca(sk);

	if (unlikely(ca->host_bw == 0)) {
		return;
	}

	clear_old_cwnds(sk);
}

static u32 powertcp_ssthresh(struct sock *sk)
{
	/* We don't do slow starts here! */
	return TCP_INFINITE_SSTHRESH;
}

static u32 powertcp_undo_cwnd(struct sock *sk)
{
	/* Never undo after a loss. */
	// TODO: Or do we?
	return tcp_sk(sk)->snd_cwnd;
}

DEFINE_POWERTCP_VARIANT(ptcp, powertcp);
DEFINE_POWERTCP_VARIANT(rttptcp, rttpowertcp);

static int __init powertcp_register(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct powertcp) > ICSK_CA_PRIV_SIZE);

	ret = tcp_register_congestion_control(&powertcp);
	if (ret) {
		return ret;
	}

	ret = tcp_register_congestion_control(&rttpowertcp);
	if (ret) {
		return ret;
	}

	return 0;
}

static void __exit powertcp_unregister(void)
{
	tcp_unregister_congestion_control(&powertcp);
}

module_init(powertcp_register);
module_exit(powertcp_unregister);

MODULE_ALIAS("tcp_rttpowertcp");
MODULE_AUTHOR("Jörn-Thorben Hinz");
MODULE_DESCRIPTION("PowerTCP congestion control");
MODULE_LICENSE("Dual MIT/GPL");
