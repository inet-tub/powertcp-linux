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

#include "tcp_powertcp_debugfs.h"

#include <linux/ethtool.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <linux/units.h>
#include <net/tcp.h>

enum powertcp_variant {
	POWERTCP_POWERTCP = 0,
	POWERTCP_RTTPOWERTCP = 1,
};

struct old_cwnd {
	u32 snd_nxt;
	u32 cwnd;
	struct list_head list;
};

struct powertcp_ops {
	long (*norm_power)(const struct sock *sk, const struct rate_sample *rs,
			   long base_rtt_us);
	void (*reset)(struct sock *sk, long base_rtt_us);
	bool (*update_old)(struct sock *sk, const struct rate_sample *rs,
			   long p_smooth);
	u32 (*update_window)(struct sock *sk, u32 cwnd_old, long norm_power);
};

struct powertcp {
	// TODO: Sort members in a cache-friendly way if necessary.

	union {
		struct {
			// TODO: Add variant-specific members as needed.
		} ptcp;
		struct {
			u32 last_updated;
			long prev_rtt_us;
			u64 t_prev;
		} rttptcp;
	};

	const struct powertcp_ops *ops;

	// powertcp_cong_control() seems to (unexpectedly) get called once before
	// powertcp_init(). Remember whether we did the initialization.
	// TODO: Check, why that's the case.
	bool initialized;

	int beta;

	// TODO: Investigate if this frequently updated list decreases performance
	// and another data structure would improve that.
	struct list_head old_cwnds;

	long p_smooth;

	unsigned long host_bw; /* Mbit/s */
};

static const unsigned long fallback_host_bw = 1000; /* Mbit/s */
static const long gamma_scale = (1L << 10);
static const long norm_power_scale = (1L << 16);

static int beta = -1;
static int expected_flows = 10;
static int gamma = 0.9 * gamma_scale;
// TODO: Don't force selection of an algorithm variant. Ideally detect what's
// possible on e.g. the first received ACK or even SYN(ACK)---with or without
// INT.
static int variant = POWERTCP_POWERTCP;

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
static long base_rtt(const struct sock *sk, const struct rate_sample *rs)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	u32 min_rtt = tcp_min_rtt(tp);
	if (likely(min_rtt != ~0U)) {
		return min_rtt;
	}

	if (rs && rs->rtt_us != -1L) {
		return rs->rtt_us;
	}

	/* bbr_init_pacing_rate_from_rtt() also uses this as fallback. */
	return USEC_PER_SEC;
}

static u16 sk_inet_id(const struct sock *sk)
{
	return inet_sk(sk)->inet_id;
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
static u32 get_cwnd(const struct sock *sk)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Use the current cwnd initially or if looking for this ack_seq comes up
	 * empty:
	 */
	u32 cwnd_old = tp->snd_cwnd;
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
			pr_debug("inet_id=%u: got link speed: %lu Mbit/s\n",
				 sk_inet_id(sk), bw);
		} else {
			pr_warn("link speed unavailable, using fallback: %lu Mbit/s\n",
				bw);
		}
	}

	return bw;
}

static void set_cwnd(struct tcp_sock *tp, u32 cwnd)
{
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
}

/* Set the socket pacing rate (bytes per second). */
static void set_rate(struct sock *sk, unsigned long rate)
{
	sk->sk_pacing_rate = min(rate, sk->sk_max_pacing_rate);
}

static void reset(struct sock *sk, long base_rtt_us)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u16 inet_id = sk_inet_id(sk);

	if (base_rtt_us == -1L) {
		base_rtt_us = base_rtt(sk, NULL);
	}

	/* Set the rate first, the initialization of snd_cwnd already uses it. */
	set_rate(sk, BITS_TO_BYTES(MEGA * ca->host_bw));
	set_cwnd(tp, sk->sk_pacing_rate * base_rtt_us / USEC_PER_SEC);
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;

	if (beta < 0) {
		ca->beta = BITS_TO_BYTES((MEGA * ca->host_bw * base_rtt_us) /
					 expected_flows / USEC_PER_SEC);
		pr_debug("inet_id=%u: automatically setting beta to %d bytes\n",
			 sk_inet_id(sk), ca->beta);
	} else {
		ca->beta = beta;
	}

	ca->p_smooth = 0;

	clear_old_cwnds(sk);

	pr_debug(
		"inet_id=%u: reset: cwnd=%u bytes, base_rtt=%lu us, rate=%lu bytes/s (~= %lu Mbit/s)\n",
		inet_id, tp->snd_cwnd, base_rtt_us, sk->sk_pacing_rate,
		sk->sk_pacing_rate * BITS_PER_BYTE / MEGA);
	powertcp_debugfs_update(inet_id, tp->snd_una, tp->snd_cwnd,
				sk->sk_pacing_rate);
}

/* Update the list of recent snd_cwnds. */
static bool update_old(struct sock *sk, long p_smooth)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	u32 ack_seq = tp->snd_una;
	u32 cwnd = tp->snd_cwnd;
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

static u32 update_window(struct sock *sk, u32 cwnd_old, long norm_power)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	u32 cwnd =
		(gamma * (norm_power_scale * cwnd_old / norm_power + ca->beta) +
		 (gamma_scale - gamma) * tp->snd_cwnd) /
		gamma_scale;
	set_cwnd(tp, cwnd);
	return cwnd;
}

static long ptcp_norm_power(const struct sock *sk, const struct rate_sample *rs,
			    long base_rtt_us)
{
	return 0;
}

static bool ptcp_update_old(struct sock *sk, const struct rate_sample *rs,
			    long p_smooth)
{
	return false;
}

static long rttptcp_norm_power(const struct sock *sk,
			       const struct rate_sample *rs, long base_rtt_us)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	long dt, rtt_grad, p_norm;
	long p_smooth = ca->p_smooth;

	if (before(tp->snd_una, ca->rttptcp.last_updated)) {
		return p_smooth ? p_smooth : norm_power_scale;
	}

	dt = tcp_stamp_us_delta(tp->tcp_mstamp, ca->rttptcp.t_prev);
	rtt_grad =
		norm_power_scale * (rs->rtt_us - ca->rttptcp.prev_rtt_us) / dt;
	p_norm = (rtt_grad + norm_power_scale) * rs->rtt_us / base_rtt_us;
	p_smooth = p_smooth ? p_smooth : p_norm;
	p_smooth =
		(p_smooth * (base_rtt_us - dt) + (p_norm * dt)) / base_rtt_us;

	pr_debug(
		"inet_id=%u: dt=%ld us, rtt_grad*%ld=%ld, p_norm*%ld=%ld, p_smooth*%ld=%ld\n",
		sk_inet_id(sk), dt, norm_power_scale, rtt_grad,
		norm_power_scale, p_norm, norm_power_scale, p_smooth);

	return p_smooth;
}

static void rttptcp_reset(struct sock *sk, long base_rtt_us)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (base_rtt_us == -1L) {
		base_rtt_us = base_rtt(sk, NULL);
	}

	ca->rttptcp.last_updated = tp->snd_nxt;
	ca->rttptcp.prev_rtt_us = base_rtt_us;
	ca->rttptcp.t_prev = tp->tcp_mstamp;

	reset(sk, base_rtt_us);
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
	ca->rttptcp.prev_rtt_us = rs->rtt_us;
	// TODO: There are multiple timestamps available here. Is there a better one?
	ca->rttptcp.t_prev = tp->tcp_mstamp;

	return true;
}

static u32 rttptcp_update_window(struct sock *sk, u32 cwnd_old, long norm_power)
{
	struct powertcp *ca = inet_csk_ca(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (before(tp->snd_una, ca->rttptcp.last_updated)) {
		return tp->snd_cwnd;
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

	if (unlikely(!ca->initialized)) {
		return;
	}

	if (ev == CA_EVENT_TX_START) {
		ca->ops->reset(sk, -1);
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

	ca->host_bw = get_host_bw(sk);
	INIT_LIST_HEAD(&ca->old_cwnds);

	/* Must be already (marked) initialized for reset() to work: */
	ca->initialized = true;
	ca->ops->reset(sk, -1);

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
	u32 cwnd_old;
	long norm_power;
	u32 cwnd;
	unsigned long rate;
	long base_rtt_us;
	bool updated;

	if (unlikely(!ca->initialized)) {
		return;
	}

	base_rtt_us = base_rtt(sk, rs);

	cwnd_old = get_cwnd(sk);
	norm_power = ca->ops->norm_power(sk, rs, base_rtt_us);
	cwnd = ca->ops->update_window(sk, cwnd_old, norm_power);
	rate = (USEC_PER_SEC * cwnd) / base_rtt_us;
	set_rate(sk, rate);
	updated = ca->ops->update_old(sk, rs, norm_power);

	if (updated) {
		u16 inet_id = sk_inet_id(sk);
		pr_debug(
			"inet_id=%u: cwnd_old=%u bytes, base_rtt=%ld us, norm_power*%ld=%ld, cwnd=%u bytes, rate=%lu bytes/s (~= %lu Mbit/s)\n",
			inet_id, cwnd_old, base_rtt_us, norm_power_scale,
			norm_power, cwnd, rate, rate * BITS_PER_BYTE / MEGA);
		powertcp_debugfs_update(inet_id, tp->snd_una, cwnd, rate);
	}
}

static void powertcp_release(struct sock *sk)
{
	const struct powertcp *ca = inet_csk_ca(sk);

	if (unlikely(!ca->initialized)) {
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

	powertcp_debugfs_init();
	return 0;
}

static void __exit powertcp_unregister(void)
{
	powertcp_debugfs_exit();
	tcp_unregister_congestion_control(&powertcp);
}

module_init(powertcp_register);
module_exit(powertcp_unregister);

MODULE_AUTHOR("Jörn-Thorben Hinz");
MODULE_DESCRIPTION("PowerTCP congestion control");
MODULE_LICENSE("Dual MIT/GPL");
