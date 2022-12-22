// SPDX-License-Identifier: GPL-2.0 OR MIT

enum { max_n_hops = 1 };

#include "powertcp_int.c"

/* TCP-INT's swlat field (which we optionally replace with a timestamp), is
 * only 24 bits long.
 */
static const unsigned int max_ts = 0xFFFFFFu;

/* In case the tx_bytes value is taken directly from a less-than-32-bit INT
 * field, its maximum value has to be known for correct wrap-around in
 * calculations.
 */
static const u32 max_tx_bytes = 0xFFFFFFFFu;

struct powertcp_int_impl {
	struct powertcp_int cached_int;
	struct powertcp_int prev_int;
};
typedef struct powertcp_int_impl powertcp_int_impl_t;
