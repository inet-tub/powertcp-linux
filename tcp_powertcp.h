/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef _TCP_POWERTCP_H
#define _TCP_POWERTCP_H

#include <linux/list.h>

#ifndef MEGA
#define MEGA 1000000UL
#endif

struct powertcp_ops;

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

	/* powertcp_cong_control() seems to (unexpectedly) get called once before
	 * powertcp_init(). ops is still NULL then, thanks to
	 * tcp_assign_congestion_control(), and we use that as an indicator whether
	 * we are initialized.
	 */
	const struct powertcp_ops *ops;

	int beta;

	// TODO: Investigate if this frequently updated list decreases performance
	// and another data structure would improve that.
	struct list_head old_cwnds;

	long p_smooth;

	unsigned long host_bw; /* Mbit/s */
};

#endif /* _TCP_POWERTCP_H */