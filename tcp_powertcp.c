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

enum powertcp_variant {
	POWERTCP_POWERTCP = 0,
	POWERTCP_RTTPOWERTCP = 1,
};

struct old_cwnd {
	u32 snd_nxt;
	unsigned long cwnd;
	struct list_head list;
};

struct powertcp_ops {
	unsigned long (*norm_power)(const struct sock *sk,
				    const struct rate_sample *rs,
				    unsigned long base_rtt_us);
	void (*reset)(struct sock *sk, enum tcp_ca_event ev,
		      unsigned long base_rtt_us);
	bool (*update_old)(struct sock *sk, const struct rate_sample *rs,
			   unsigned long p_smooth);
	unsigned long (*update_window)(struct sock *sk, unsigned long cwnd_old,
				       unsigned long norm_power);
};

static const unsigned long cwnd_scale = (1UL << 10);
static const unsigned long fallback_host_bw = 1000; /* Mbit/s */
static const unsigned long gamma_scale = (1UL << 10);
static const unsigned long power_scale = (1UL << 16);

static int base_rtt __read_mostly = -1;
static int beta __read_mostly = -1;
static int expected_flows __read_mostly = 10;
static int gamma __read_mostly = 0.9 * gamma_scale;
// TODO: Don't force selection of an algorithm variant. Ideally detect what's
// possible on e.g. the first received ACK or even SYN(ACK)---with or without
// INT.
static int variant __read_mostly = POWERTCP_POWERTCP;

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
module_param(variant, int, 0444);
MODULE_PARM_DESC(
	variant,
	"algorithm variant to use (default: 0; 0: PowerTCP (requires INT), 1: RTT-PowerTCP (standalone))");

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

	trace_reset(tp->tcp_mstamp, sk->sk_hash, ev, base_rtt_us, tp->snd_cwnd,
		    sk->sk_pacing_rate);
}

static unsigned long smooth_power(unsigned long p_smooth, unsigned long p_norm,
				  unsigned long base_rtt_us,
				  unsigned long delta_t)
{
	/* powertcp.p_smooth is initialized with 0, we don't want to smooth for the
	 * very first calculation.
	 */
	return p_smooth == 0 ? p_norm :
				     (p_smooth * (base_rtt_us - delta_t) +
				(p_norm * delta_t)) /
				       base_rtt_us;
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
	cwnd = (gamma * (power_scale * cwnd_old / norm_power + ca->beta) +
		(gamma_scale - gamma) * ca->snd_cwnd) /
	       gamma_scale;
	cwnd = max(1UL, cwnd);
	trace_update_window(sk, cwnd_old, power_scale, norm_power, cwnd);
	set_cwnd(sk, cwnd);
	return cwnd;
}

static unsigned long ptcp_norm_power(const struct sock *sk,
				     const struct rate_sample *rs,
				     unsigned long base_rtt_us)
{
	return 0;
}

static bool ptcp_update_old(struct sock *sk, const struct rate_sample *rs,
			    unsigned long p_smooth)
{
	return false;
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
	p_smooth = smooth_power(p_smooth, p_norm, base_rtt_us, delta_t);

	trace_norm_power(sk, dt, delta_t, rtt_us, rtt_grad, base_rtt_us,
			 power_scale, p_norm, p_smooth);

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

static const struct powertcp_ops ptcp_ops = {
	.norm_power = ptcp_norm_power,
	.reset = reset,
	.update_old = ptcp_update_old,
	.update_window = update_window,
};

static const struct powertcp_ops rttptcp_ops = {
	.norm_power = rttptcp_norm_power,
	.reset = rttptcp_reset,
	.update_old = rttptcp_update_old,
	.update_window = rttptcp_update_window,
};

void powertcp_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{
	struct powertcp *ca = inet_csk_ca(sk);

	if (unlikely(!ca->ops)) {
		return;
	}

	if (ev == CA_EVENT_TX_START) {
		ca->ops->reset(sk, ev, 0);
	}
}

static void powertcp_init(struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);

	if (variant != POWERTCP_RTTPOWERTCP) {
		memset(&ca->ptcp, 0, sizeof(ca->ptcp));
		ca->ops = &ptcp_ops;
	} else {
		memset(&ca->rttptcp, 0, sizeof(ca->rttptcp));
		ca->ops = &rttptcp_ops;
	}

	if (beta < 0) {
		ca->beta = ULONG_MAX;
	} else {
		ca->beta = beta;
	}
	ca->host_bw = get_host_bw(sk);
	INIT_LIST_HEAD(&ca->old_cwnds);

	ca->ops->reset(sk, CA_EVENT_CWND_RESTART, 0);

	/* We do want sk_pacing_rate to be respected: */
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

static void powertcp_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	/* cong_control, if assigned in tcp_congestion_ops, becomes the main
	 * congestion control function and is responsible for setting cwnd and rate.
	*/

	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	unsigned long cwnd_old;
	unsigned long norm_power;
	unsigned long cwnd;
	unsigned long rate;
	unsigned long base_rtt_us;
	bool updated;

	if (unlikely(!ca->ops)) {
		return;
	}

	base_rtt_us = get_base_rtt(sk, rs);
	update_beta(sk, base_rtt_us);

	cwnd_old = get_cwnd(sk);
	norm_power = ca->ops->norm_power(sk, rs, base_rtt_us);
	cwnd = ca->ops->update_window(sk, cwnd_old, norm_power);
	rate = (USEC_PER_SEC * cwnd * tp->mss_cache) / base_rtt_us / cwnd_scale;
	set_rate(sk, rate);
	updated = ca->ops->update_old(sk, rs, norm_power);

	if (updated) {
		trace_new_ack(sk);
	}
}

static void powertcp_release(struct sock *sk)
{
	const struct powertcp *ca = inet_csk_ca(sk);

	if (unlikely(!ca->ops)) {
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

static struct tcp_congestion_ops powertcp __read_mostly = {
	.cong_control = powertcp_cong_control,
	.cwnd_event = powertcp_cwnd_event,
	.init = powertcp_init,
	.name = "powertcp",
	.owner = THIS_MODULE,
	.release = powertcp_release,
	.ssthresh = powertcp_ssthresh,
	.undo_cwnd = powertcp_undo_cwnd,
};

static int __init powertcp_register(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct powertcp) > ICSK_CA_PRIV_SIZE);

	ret = tcp_register_congestion_control(&powertcp);
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

MODULE_AUTHOR("Jörn-Thorben Hinz");
MODULE_DESCRIPTION("PowerTCP congestion control");
MODULE_LICENSE("Dual MIT/GPL");
