/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef _TCP_POWERTCP_H
#define _TCP_POWERTCP_H

#include "powertcp_defs.h"

#include <linux/list.h>

#ifndef MEGA
#define MEGA 1000000UL
#endif

#define POWERTCP_STRUCT(struct_name, fields)                                                \
	struct struct_name {                                                                \
		unsigned long base_rtt;                                                     \
		unsigned long snd_cwnd;                                                     \
                                                                                            \
		unsigned long beta;                                                         \
                                                                                            \
		/* TODO: Investigate if this frequently updated list decreases \
		 * performance and another data structure would improve that. \
		 */            \
		struct list_head old_cwnds;                                                 \
                                                                                            \
		unsigned long p_smooth;                                                     \
                                                                                            \
		/* powertcp_cong_control() seems to (unexpectedly) get called once before \
		 * powertcp_init(). host_bw is still 0 then, thanks to \
		 * tcp_assign_congestion_control(), and we use that as an indicator whether \
		 * we are initialized. \
		 */ \
		unsigned long host_bw; /* Mbit/s */                                         \
                                                                                            \
		fields                                                                      \
	}
#define POWERTCP_STRUCT_FIELDS(...) __VA_ARGS__

// clang-format off
POWERTCP_STRUCT(powertcp, POWERTCP_STRUCT_FIELDS());

POWERTCP_STRUCT(ptcp_powertcp,
	POWERTCP_STRUCT_FIELDS(
		// TODO: Add variant-specific members as needed.
	)
);

POWERTCP_STRUCT(rttptcp_powertcp,
	POWERTCP_STRUCT_FIELDS(
		u32 last_updated;
		unsigned long prev_rtt_us;
		u64 t_prev;
	)
);
// clang-format on

#undef POWERTCP_STRUCT
#undef POWERTCP_STRUCT_FIELDS

#endif /* _TCP_POWERTCP_H */
