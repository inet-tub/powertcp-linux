// SPDX-License-Identifier: GPL-2.0 OR MIT

enum { max_n_hops = 1 };

#include "powertcp_int.c"

/* In case the ts value is taken directly from a less-than-32-bit INT field,
 * its maximum value has to be known for correct wrap-around in calculations.
 */
static const unsigned int max_ts = -1;

/* In case the tx_bytes value is taken directly from a less-than-32-bit INT
 * field, its maximum value has to be known for correct wrap-around in
 * calculations.
 */
static const u32 max_tx_bytes = -1;

struct powertcp_int_impl {
};

typedef struct powertcp_int_impl *powertcp_int_impl_t;
