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

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

/* TODO: Select proper TCP option-kind: */
static const int powertcp_opt_hpcc = 0x42;
static const int hpcc_min_opsize = 2 + 2;
static const int hpcc_max_opsize = 2 + 42;

/*
 * Data format for INT adopted (for now) from:
 *    Li, Yuliang, et al.
 *    "HPCC: High precision congestion control."
 *    Proceedings of the ACM Special Interest Group on Data Communication. 2019. 44-58.
 *
 * See figure 7, "The packet format of HPCC":
 *                                                                | 1st hop
 *  7   6   5   4   3   2   1   0 | 7   6   5   4   3   2   1   0 | 7   6   5   4   3   2   1   0 | 7   6   5   4   3   2   1   0
 *  nHop          | PathID                                        | B             | TS
 *
 *  7   6   5   4   3   2   1   0 | 7   6   5   4   3   2   1   0 | 7   6   5   4   3   2   1   0 | 7   6   5   4   3   2   1   0
 *                                                | txBytes
 *                                                                | 2nd hop ...
 *  7   6   5   4   3   2   1   0 | 7   6   5   4   3   2   1   0 | 7   6   5   4   3   2   1   0
 *  qLen                                                          | ...
 *
 */
struct hpcc_hop_int {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	// clang-format off
	// TODO: I probably messed this up:
	u64 qlen: 16,
	    tx_bytes: 20,
	    ts: 24,
	    bandwidth: 4;
	// clang-format on
#elif defined(__BIG_ENDIAN_BITFIELD)
	// clang-format off
	u64 bandwidth: 4,
	    ts: 24,
	    tx_bytes: 20,
	    qlen: 16;
	// clang-format on
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
};

union hpcc_hop_int_word {
	struct hpcc_hop_int hop_int;
	u64 word;
};

struct hpcc_int_head {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	// clang-format off
	u16 path_id: 12,
	    n_hop:   4;
	// clang-format on
#elif defined(__BIG_ENDIAN_BITFIELD)
	// clang-format off
	u16 n_hop:   4,
	    path_id: 12;
	// clang-format on
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
};

union hpcc_int_head_word {
	struct hpcc_int_head int_head;
	u16 word;
};

static const struct powertcp_int *get_int(struct sock *sk,
					  const struct powertcp_int *prev_int)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	return &ca->ptcp.curr_int;
}

static const struct powertcp_int *get_prev_int(struct sock *sk)
{
	const struct powertcp *ca = inet_csk_ca(sk);
	return &ca->ptcp.prev_int;
}

static u32 hpcc_bandwidth_to_bytes(u32 bw)
{
	switch (bw) {
		/* TODO: Settle on values for the 4-bit bandwidth field in the TCP
		 * option.
		 */
	}

	return BITS_TO_BYTES(MEGA * 1000);
}

static void ptcp_parse_hpcc_opt(struct sock *sk, const unsigned char *ptr,
				int len)
{
	struct powertcp *ca = inet_csk_ca(sk);
	struct powertcp_int *curr_int = &ca->ptcp.curr_int;
	union hpcc_int_head_word head_word;
	int i;

	head_word.word = get_unaligned_be16(ptr);
	*curr_int = (struct powertcp_int){
		.n_hop = head_word.int_head.n_hop,
		.path_id = head_word.int_head.path_id,
	};
	ptr += sizeof(head_word.word);
	len -= sizeof(head_word.word);

	for (i = 0; i < curr_int->n_hop && i < max_n_hops; ++i) {
		union hpcc_hop_int_word hop_word;

		if (len < sizeof(hop_word.word)) {
			break;
		}

		hop_word.word = get_unaligned_be64(ptr);
		curr_int->hops[i] = (struct powertcp_hop_int){
			.qlen = hop_word.hop_int.qlen,
			.tx_bytes = hop_word.hop_int.tx_bytes,
			.ts = hop_word.hop_int.ts,
			.bandwidth = hpcc_bandwidth_to_bytes(
				hop_word.hop_int.bandwidth),
		};

		ptr += sizeof(hop_word.word);
		len -= sizeof(hop_word.word);
	}
}

static unsigned int ptcp_nf_hook(void *priv, struct sk_buff *skb,
				 const struct nf_hook_state *state)
{
	struct sock *sk = state->sk;
	const struct inet_connection_sock *icsk = inet_csk(sk);

	const unsigned char *ptr;
	const struct tcphdr *th;
	int length;

	if (!sk_is_tcp(sk) || icsk->icsk_ca_ops->key != *(u32 *)priv) {
		return NF_ACCEPT;
	}

	/* Trimmed-down version of tcp_parse_options(): */
	th = tcp_hdr(skb);
	length = (th->doff * 4) - sizeof(struct tcphdr);

	ptr = (const unsigned char *)(th + 1);

	while (length > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			return NF_ACCEPT;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			if (length < 2) {
				return NF_ACCEPT;
			}
			opsize = *ptr++;
			if (opsize < 2) {
				return NF_ACCEPT;
			}
			if (opsize > length) {
				return NF_ACCEPT;
			}
			switch (opcode) {
			case powertcp_opt_hpcc:
				if (opsize >= hpcc_min_opsize &&
				    opsize <= hpcc_max_opsize) {
					ptcp_parse_hpcc_opt(sk, ptr,
							    opsize - 2);
				}
				return NF_ACCEPT;
			}
			ptr += opsize - 2;
			length -= opsize;
			break;
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops ptcp_nf_ops[] __read_mostly = {
	{
		.hook = ptcp_nf_hook,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = ptcp_nf_hook,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_LAST,
	},
};

static int __net_init ptcp_nf_register(struct net *net)
{
	pr_warn("registering PowerTCP Netfilter hooks\n");
	return nf_register_net_hooks(net, ptcp_nf_ops, ARRAY_SIZE(ptcp_nf_ops));
}

static void __net_init ptcp_nf_unregister(struct net *net)
{
	nf_unregister_net_hooks(net, ptcp_nf_ops, ARRAY_SIZE(ptcp_nf_ops));
}

static struct pernet_operations ptcp_pernet_ops __read_mostly = {
	.init = ptcp_nf_register,
	.exit = ptcp_nf_unregister,
};

static int register_int(struct tcp_congestion_ops *cong_ops)
{
	int ret;
	int i;
	u32 *nf_ops_priv;

	nf_ops_priv = kmalloc(sizeof(cong_ops->key), GFP_KERNEL);
	if (!nf_ops_priv) {
		return -1;
	}

	*nf_ops_priv = cong_ops->key;
	for (i = 0; i < ARRAY_SIZE(ptcp_nf_ops); ++i) {
		ptcp_nf_ops[i].priv = nf_ops_priv;
	}

	ret = register_pernet_subsys(&ptcp_pernet_ops);
	if (ret) {
		kfree(ptcp_nf_ops[0].priv);
		return -1;
	}

	return 0;
}

static void unregister_int(struct tcp_congestion_ops *cong_ops)
{
	unregister_pernet_subsys(&ptcp_pernet_ops);
	kfree(ptcp_nf_ops[0].priv);
}
