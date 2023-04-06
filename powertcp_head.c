// SPDX-License-Identifier: GPL-2.0 OR MIT

#ifndef POWERTCP_CONG_OPS_ATTRS
#define POWERTCP_CONG_OPS_ATTRS
#endif

#ifndef POWERTCP_CONG_OPS_FUNC
#define POWERTCP_CONG_OPS_FUNC(name, args...) name(args)
#endif

#ifndef POWERTCP_CONG_OPS_FUNC_PTR
#define POWERTCP_CONG_OPS_FUNC_PTR
#endif

#ifndef POWERTCP_CONG_OPS_NAME_PREFIX
#define POWERTCP_CONG_OPS_NAME_PREFIX
#endif

#ifndef POWERTCP_LIKELY
#define POWERTCP_LIKELY(cond) cond
#endif

#ifndef POWERTCP_PARAM_ATTRS
#define POWERTCP_PARAM_ATTRS
#endif

#ifndef POWERTCP_UNLIKELY
#define POWERTCP_UNLIKELY(cond) cond
#endif

#ifndef __stringify
#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)
#endif

struct old_cwnd {
	u32 snd_nxt;
	unsigned long cwnd;
};

#define POWERTCP_STRUCT(struct_name, ...)                                                   \
	struct struct_name {                                                                \
		unsigned long base_rtt;                                                     \
		unsigned long snd_cwnd;                                                     \
                                                                                            \
		unsigned long beta; /* number of packets scaled by cwnd_scale */            \
                                                                                            \
		struct old_cwnd old_cwnd;                                                   \
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
		__VA_ARGS__                                                                 \
	}
#define POWERTCP_STRUCT_FIELDS(fields) fields

// clang-format off
POWERTCP_STRUCT(powertcp);

POWERTCP_STRUCT(ptcp_powertcp,
	POWERTCP_STRUCT_FIELDS(
		powertcp_int_impl_t int_impl;
	)
);

POWERTCP_STRUCT(rttptcp_powertcp,
	POWERTCP_STRUCT_FIELDS(
		u32 last_updated;
		unsigned long prev_rtt_us;
		u64 t; /* in ns */
		u64 t_prev; /* in ns */
	)
);
// clang-format on

#undef POWERTCP_STRUCT
#undef POWERTCP_STRUCT_FIELDS

POWERTCP_PARAM_ATTRS long base_rtt = default_base_rtt;
POWERTCP_PARAM_ATTRS long beta = default_beta; /* Number of packets */
POWERTCP_PARAM_ATTRS long expected_flows = default_expected_flows;
POWERTCP_PARAM_ATTRS long gamma = default_gamma;
POWERTCP_PARAM_ATTRS long hop_bw = default_hop_bw; /* Mbit/s */
POWERTCP_PARAM_ATTRS long host_bw = fallback_host_bw; /* Mbit/s */
