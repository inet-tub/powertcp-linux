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
#include <net/tcp.h>

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
	.cong_control = 0 /* optional */,

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
	.init = 0 /* optional */,

	/* cleanup private data  (optional) */
	.release = 0 /* optional */,
};

static int __init powertcp_register(void)
{
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
