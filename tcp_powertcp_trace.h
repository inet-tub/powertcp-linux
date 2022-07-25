// SPDX-License-Identifier: GPL-2.0 OR MIT
#undef TRACE_SYSTEM
#define TRACE_SYSTEM powertcp

#if !defined(_TRACE_POWERTCP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_POWERTCP_H

#include <linux/tracepoint.h>

// clang-format off
TRACE_EVENT(cong_control,
	TP_PROTO(const struct powertcp_trace_event *ev),
	TP_ARGS(ev),
	TP_STRUCT__entry(
		__field(u64, time)
		__field(unsigned int, sock_hash)
		__field(u32, cwnd)
		__field(unsigned long, rate)
		__field(unsigned long, p_norm)
		__field(unsigned long, p_smooth)
		__field(unsigned long, qlen)
		__field(__u32, tx_bytes_diff)
		__field(__u32, delta_t)
	),
	TP_fast_assign(
		__entry->time = ev->time;
		__entry->sock_hash = ev->sock_hash;
		__entry->cwnd = ev->cwnd;
		__entry->rate = ev->rate;
		__entry->p_norm = ev->p_norm;
		__entry->p_smooth = ev->p_smooth;
		__entry->qlen = ev->qlen;
		__entry->tx_bytes_diff = ev->tx_bytes_diff;
		__entry->delta_t = ev->delta_t;
	),
	TP_printk("time=%llu us sock_hash=%u cwnd=%u rate=%ld Mbit/s p_norm=%ld p_smooth=%ld qlen=%ld tx_bytes_diff=%u bytes delta_t=%u ns",
		__entry->time,
		__entry->sock_hash,
		__entry->cwnd,
		BITS_PER_BYTE * __entry->rate / MEGA,
		__entry->p_norm,
		__entry->p_smooth,
		__entry->qlen,
		__entry->tx_bytes_diff,
		__entry->delta_t
	)
);
// clang-format on

#endif /* _TRACE_POWERTCP_H */

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE tcp_powertcp_trace
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

/* This part must be outside protection */
#include <trace/define_trace.h>
