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

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <net/tcp.h>

/*
# PowerTCP algorithm

# ack contains an INT header with
# sequence of per-hop egress port
# meta-data accessed as ack.H[i]

Input: ack, prevInt
Output: cwnd, rate

procedure NEW_ACK (ack):
	cwnd_old = GET_CWND(ack.seq)
	normPower = NORM_POWER(ack)
	UPDATE_WINDOW(normPower, cwnd_old)
	rate = cwnd / τ
	prevInt = ack.H
	UPDATE_OLD(cwnd, ack.seq)

function NORM_POWER(ack):
	Γ_norm = 0
	for each egress port i on the path do
		dt = ack.H[i].ts - prevInt[i].ts
		q̇  = (ack.H[i].qlen - prevInt[i].qlen) / dt      # dq / dt
		λ = (ack.H[i].txBytes - prevInt[i].txBytes) / dt
		λ = q̇ + µ                                     # λ: Current
		BDP = ack.H[i].b * τ
		ν = ack.H[i].qlen + BDP
		Γ = λ * ν
		e = ack.H[i].b^2 * τ
		Γ'_norm = Γ' / e                              # Γ'_norm: Normalized power
		if Γ' > Γ_norm then
			Γ_norm = Γ'
			∆t = dt
		end if
	end for
	Γ_smooth = (Γ_smooth * (τ - ∆t) + (Γ_norm * ∆t)) / τ # Smoothing
	return Γ_smooth

function UPDATE_WINDOW(power, ack):
	cwnd = γ * (cwnd_old / normPower + β) + (1 - γ) * cwnd
	                                                  # γ : EWMA parameter
	                                                  # β: Additive Increase
	return cwnd
*/

/*
# θ-PowerTCP (w/o switch support) algorithm

# t_c is the timestamp when ACK is received

Input: ack
Output: cwnd, rate

procedure NEW_ACK(ack):
	cwnd_old = GET_CWND(ack.seq)
	normPower = NORM_POWER(ack)
	UPDATE_WINDOW(normPower, cwnd_old)
	rate = cwnd / τ
	prevRTT = RTT
	t_c_prev = t_c
	UPDATE_OLD(cwnd, ack.seq)

function NORM_POWER(ack):
	dt = t_c - t_c_prev
	θ̇ = (RTT - prevRTT) / dt                    # dRTT / dt
	Γ_norm = ((θ̇  + 1) * RTT) / τ                # Γ_norm: Normalized
	Γ_smooth = (Γ_smooth * (τ - ∆t) + (Γ_norm * ∆t)) / τ
	return Γ_smooth

function UPDATE_WINDOW(power, ack):
	if ack.seq < lastUpdated then               # per RTT
		return cwnd
	end if
	cwnd = γ * (cwnd_old / normPower + β) + (1 - γ) * cwnd
	                                            #. γ : EWMA parameter
	                                            #. β: Additive Increase
	lastUpdated = snd_nxt
	return cwnd
*/

enum powertcp_variant {
	POWERTCP_POWERTCP = 0,
	POWERTCP_RTTPOWERTCP = 1,
};

struct powertcp {
	union {
		struct {
			// TODO: Add variant-specific members as needed.
		} ptcp;
		struct {
			// TODO: Add variant-specific members as needed.
		} rttptcp;
	};

	//tbd (*norm_power)(ack);
	//tbd (*update_old)(cwnd, ack);
	//tbd (*update_window)(power, ack);

	// TODO: Add common members as needed.
};

// TODO: Check what's a sensible default for beta.
// TODO: Automatically calculate the value for beta, based on the recommendation
// in sec. 3.3, Parameters. Maybe take the expected number of flows N in an
// additional parameter.
static int beta = 1000;
static int gamma = 900;
// TODO: Don't force selection of an algorithm variant. Ideally detect what's
// possible on e.g. the first received ACK or even SYN(ACK)---with or without
// INT.
static int variant = POWERTCP_POWERTCP;

module_param(beta, int, 0444);
MODULE_PARM_DESC(beta, "additive increase (default: 1000)");
module_param(gamma, int, 0444);
MODULE_PARM_DESC(
	gamma,
	"exponential moving average weight, times 1000 (default: 900 = 0,9)");
module_param(variant, int, 0444);
MODULE_PARM_DESC(
	variant,
	"algorithm variant to use (default: 0; 0: PowerTCP (requires INT), 1: RTT-PowerTCP (standalone))");

/*
static void ptcp_norm_power(ack)
{
}
*/

/*
static void ptcp_update_old(power, ack)
{
}
*/

/*
static void ptcp_update_window(cwnd, ack)
{
}
*/

/*
static void rttptcp_norm_power(ack)
{
}
*/

/*
static void rttptcp_update_old(power, ack)
{
}
*/

/*
static void rttptcp_update_window(cwnd, ack)
{
}
*/

static void powertcp_init(struct sock *sk)
{
	struct powertcp *ca = inet_csk_ca(sk);

	if (variant != POWERTCP_RTTPOWERTCP) {
		memset(&ca->ptcp, 0, sizeof(ca->ptcp));
		//ca->norm_power = ptcp_norm_power;
		//ca->update_old = ptcp_update_old;
		//ca->update_window = ptcp_update_window;
	} else {
		memset(&ca->rttptcp, 0, sizeof(ca->rttptcp));
		//ca->norm_power = rttptcp_norm_power;
		//ca->update_old = rttptcp_update_old;
		//ca->update_window = rttptcp_update_window;
	}
}

static void powertcp_cong_control(struct sock *sk, const struct rate_sample *rs)
{
	/* cong_control, if assigned in tcp_congestion_ops, becomes the main
	 * congestion control function and responsible for setting cwnd, rate and
	 * so on (if I'm not mistaken).
	*/

	struct powertcp *ca = inet_csk_ca(sk);

	// NOTE: Just based on the pseudo-code, might actually be done slightly
	// different in real code:
	//tbd cwnd_old = get_cwnd(); // this is likely just tcp_sock.snd_cwnd
	//tbd norm_power = ca->norm_power(ack argument);
	//tbd cwnd = ca->update_window(norm_power, cwnd_old);
	//tbd ca->update_old(cwnd, ack);
}

static struct tcp_congestion_ops powertcp __read_mostly = {
	/* return slow start threshold (required) */
	.ssthresh = 0 /* required */,

	/* do new cwnd calculation (required) */
	.cong_avoid = 0 /* required */,

	/* call before changing ca_state (optional) */
	.set_state = 0 /* optional */,

	/* call when cwnd event occurs (optional) */
	.cwnd_event = 0 /* optional */,

	/* call when ack arrives (optional) */
	.in_ack_event = 0 /* optional */,

	/* hook for packet ack accounting (optional) */
	.pkts_acked = 0 /* optional */,

	/* override sysctl_tcp_min_tso_segs */
	.min_tso_segs = 0 /* optional */,

	/* call when packets are delivered to update cwnd and pacing rate, after all
	 * the ca_state processing. (optional) */
	.cong_control = powertcp_cong_control,

	/* new value of cwnd after loss (required) */
	.undo_cwnd = 0 /* required */,

	/* returns the multiplier used in tcp_sndbuf_expand (optional) */
	.sndbuf_expand = 0 /* optional */,

	/* control/slow paths put last */
	/* get info for inet_diag (optional) */
	.get_info = 0 /* optional */,

	.name = "powertcp",
	.owner = THIS_MODULE,

	/* initialize private data (optional) */
	.init = powertcp_init,

	/* cleanup private data  (optional) */
	.release = 0 /* optional */,
};

static int __init powertcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct powertcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&powertcp);
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
