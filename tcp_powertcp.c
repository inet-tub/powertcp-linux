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

#include "powertcp_defs.h"

#include <linux/ethtool.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/types.h>
#include <net/tcp.h>

#include "powertcp_trace.h"

#ifndef MEGA
#define MEGA 1000000UL
#endif

#define CREATE_TRACE_POINTS
#include "tcp_powertcp_trace.h"

#ifndef BITS_TO_BYTES
#define BITS_TO_BYTES(nr) __KERNEL_DIV_ROUND_UP(nr, BITS_PER_TYPE(char))
#endif

#define POWERTCP_CONG_OPS_ATTRS static __read_mostly
#define POWERTCP_CONG_OPS_FUNC_ATTRS static
#define POWERTCP_PARAM_ATTRS static __read_mostly
#define POWERTCP_UNLIKELY unlikely

#include "powertcp_no-int_head.c"

#include "powertcp_head.c"

module_param(base_rtt, long, 0444);
MODULE_PARM_DESC(
	base_rtt,
	"base (minimum) round-trip time (RTT) in us (default: -1; -1: automatically detect)");
module_param(beta, long, 0444);
MODULE_PARM_DESC(beta,
		 "additive increase (default: -1; -1: automatically set beta)");
module_param(expected_flows, long, 0444);
MODULE_PARM_DESC(expected_flows,
		 "expected number of flows sharing the host NIC (default: 10)");
module_param(gamma, long, 0444);
MODULE_PARM_DESC(gamma, "exponential moving average weight, times " __stringify(
				gamma_scale) "(default: 921 ~= 0,9)");
module_param(hop_bw, long, 0444);
MODULE_PARM_DESC(hop_bw, "hop bandwidth in Mbit/s");
module_param(host_bw, long, 0444);
MODULE_PARM_DESC(
	host_bw,
	"host NIC bandwidth in Mbit/s (default: -1; -1: detect from socket)");

/* Look for the host bandwidth (in Mbit/s). */
static unsigned long get_host_bw(struct sock *sk)
{
	const struct dst_entry *dst;
	unsigned long bw = fallback_host_bw;

	if (host_bw > 0) {
		return host_bw;
	}

	dst = __sk_dst_get(sk);
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

static void output_trace_event(struct powertcp_trace_event *trace_event)
{
	trace_event->time = ktime_get_ns();
	trace_cong_control(trace_event);
}

static void require_pacing(struct sock *sk)
{
	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);
}

/* Set the socket pacing rate (bytes per second). */
static void set_rate(struct sock *sk, unsigned long rate)
{
	/* Before 4.20, sk_max_pacing_rate was only a u32. Use explicit min_t with
	 * type here to avoid a warning on those older kernels.
	 */
	sk->sk_pacing_rate = min_t(unsigned long, rate, sk->sk_max_pacing_rate);
}

static bool tracing_enabled(void)
{
	return trace_cong_control_enabled();
}

/* cong_avoid was previously non-optional in tcp_congestion_ops for a BPF CA.
 * For the module implementation it can just be set to a NULL pointer.
 */
static const void *const powertcp_cong_avoid = NULL;

#include "powertcp_no-int.c"

#include "powertcp.c"

static int __init powertcp_register(void)
{
	int ret;

	powertcp.owner = THIS_MODULE;
	ret = tcp_register_congestion_control(&powertcp);
	if (ret) {
		return ret;
	}

	ret = register_int(&powertcp);
	if (ret) {
		tcp_unregister_congestion_control(&powertcp);
		return ret;
	}

	rttpowertcp.owner = THIS_MODULE;
	ret = tcp_register_congestion_control(&rttpowertcp);
	if (ret) {
		return ret;
	}

	return 0;
}

static void __exit powertcp_unregister(void)
{
	unregister_int(&powertcp);
	tcp_unregister_congestion_control(&powertcp);
	tcp_unregister_congestion_control(&rttpowertcp);
}

module_init(powertcp_register);
module_exit(powertcp_unregister);

MODULE_ALIAS("tcp_rttpowertcp");
MODULE_AUTHOR("Jörn-Thorben Hinz");
MODULE_DESCRIPTION("PowerTCP congestion control");
MODULE_LICENSE("Dual MIT/GPL");
