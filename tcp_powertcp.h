/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef _TCP_POWERTCP_H
#define _TCP_POWERTCP_H

#include "powertcp_defs.h"

#ifdef POWERTCP_INT_HEADER_FILE
#include <linux/stringify.h>

/*
 * The header of an INT implementation must provide:
 *
 *    enum { max_n_hops };
 */
#include __stringify(POWERTCP_INT_HEADER_FILE)
#endif

#include <linux/list.h>

#ifndef MEGA
#define MEGA 1000000UL
#endif

#ifdef POWERTCP_INT_HEADER_FILE
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

struct powertcp_int_impl;
#endif

struct powertcp {
	unsigned long base_rtt;
	unsigned long snd_cwnd;

	union {
#ifdef POWERTCP_INT_HEADER_FILE
		struct {
			struct powertcp_int_impl *int_impl;
		} ptcp;
#endif
		struct {
			u32 last_updated;
			unsigned long prev_rtt_us;
			u64 t_prev;
		} rttptcp;
	};

	unsigned long beta;

	// TODO: Investigate if this frequently updated list decreases performance
	// and another data structure would improve that.
	struct list_head old_cwnds;

	unsigned long p_smooth;

	/* powertcp_cong_control() seems to (unexpectedly) get called once before
	 * powertcp_init(). host_bw is still 0 then, thanks to
	 * tcp_assign_congestion_control(), and we use that as an indicator whether
	 * we are initialized.
	 */
	unsigned long host_bw; /* Mbit/s */
};

#endif /* _TCP_POWERTCP_H */
