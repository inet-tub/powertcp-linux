// SPDX-License-Identifier: GPL-2.0 OR MIT

struct powertcp_hop_int {
	u32 bandwidth; /* in MByte/s */
	u32 ts; /* careful: in ns */
	u32 tx_bytes;
	u32 qlen;
};

struct powertcp_int {
	int n_hop;
	int path_id;
	struct powertcp_hop_int hops[max_n_hops];
};
