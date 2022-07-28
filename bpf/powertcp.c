// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Loader and configuration tool for the eBPF implementation of the PowerTCP
 * congestion control algorithm.
 *
 * Author:
 *   Jörn-Thorben Hinz, TU Berlin, 2022.
 */
#include "powertcp.skel.h"
#include "powertcp_defs.h"

#include "tcp_int.h"

#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct powertcp_param {
	const char *name;
	char type;
	size_t rodata_off;
	double scale;
};

#define POWERTCP_RODATA_OFFSET(member)                                         \
	offsetof(struct powertcp_bpf__rodata, member)
/* The scale value is irrelevant for integer parameters. */
static const struct powertcp_param params[] = {
	{ "base_rtt", 'i', POWERTCP_RODATA_OFFSET(base_rtt), 1.0 },
	{ "beta", 'f', POWERTCP_RODATA_OFFSET(beta), cwnd_scale },
	{ "expected_flows", 'i', POWERTCP_RODATA_OFFSET(expected_flows), 1.0 },
	{ "gamma", 'f', POWERTCP_RODATA_OFFSET(gamma), gamma_scale },
	{ "hop_bw", 'i', POWERTCP_RODATA_OFFSET(hop_bw), 1.0 },
	{ "host_bw", 'i', POWERTCP_RODATA_OFFSET(host_bw), 1.0 },
	{ 0 }
};
#undef POWERTCP_RODATA_OFFSET

static int parse_param(char *param_arg, struct powertcp_bpf__rodata *rodata)
{
	const char *tok = strtok(param_arg, "=");
	if (!tok) {
		tok = "";
	}

	const struct powertcp_param *param;
	for (param = params; param->name; ++param) {
		if (strcmp(tok, param->name) == 0) {
			break;
		}
	}

	if (!param->name) {
		fprintf(stderr, "Unknown argument '%s'\n", tok);
		return -1;
	}

	tok = strtok(NULL, "=");
	if (!tok) {
		tok = "";
	}

	char *end;
	const char *reason;
	long val;
	errno = 0;
	switch (param->type) {
	case 'f':
		reason = "Not a floating-point number";
		val = strtod(tok, &end) * param->scale;
		break;
	case 'i':
		reason = "Not an integer number";
		val = strtol(tok, &end, 10);
		break;
	default:
		assert(false);
		return -1;
	}

	if (end == tok || *end != '\0' || errno != 0) {
		fprintf(stderr, "Invalid value '%s' for parameter %s: %s\n",
			tok, param->name,
			errno != 0 ? strerror(errno) : reason);
		return -1;
	}

	int *rodata_param = (int *)((char *)rodata + param->rodata_off);
	/* TODO: Maybe check if a value is in the allowed range. Or do that in the
	 * BPF code.
	 */
	*rodata_param = val;
	return 0;
}

static int attach_struct_ops(struct bpf_map *struct_ops)
{
	struct bpf_link *link = bpf_map__attach_struct_ops(struct_ops);
	if (libbpf_get_error(link)) {
		if (errno == EEXIST) {
			fprintf(stderr, "%s is already registered, skipping\n",
				bpf_map__name(struct_ops));
			return 0;
		}

		fprintf(stderr, "attach_struct_ops(%s): %s\n",
			bpf_map__name(struct_ops), strerror(errno));
		return -1;
	}

	/* Have to __disconnect() before __destroy() so the attached struct_ops
	 * outlive this userspace program.
	 */
	bpf_link__disconnect(link);
	bpf_link__destroy(link);
	return 0;
}

static int delete_struct_ops(const char *map_name)
{
	int r = 0;
	int fd = -1;
	__u32 id = 0;
	struct bpf_map_info *info;
	__u32 info_len = sizeof(*info);
	const int zero = 0;

	info = calloc(1, info_len);
	if (!info) {
		perror("calloc");
		return -1;
	}

	while (true) {
		if (bpf_map_get_next_id(id, &id)) {
			if (errno != ENOENT) {
				perror("map_get_next_id");
				r = -1;
			}
			goto fail;
		}

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT) {
				continue;
			}
			perror("map_get_fd_by_id");
			r = -1;
			goto fail;
		}

		if (bpf_obj_get_info_by_fd(fd, info, &info_len)) {
			perror("obj_get_info_by_fd");
			r = -1;
			goto fail;
		}

		if (info->type == BPF_MAP_TYPE_STRUCT_OPS &&
		    0 == strcmp(map_name, info->name)) {
			break;
		}

		close(fd);
		fd = -1;
	}

	if (bpf_map_delete_elem(fd, &zero)) {
		perror("map_delete_elem");
		r = -1;
	}

fail:
	if (fd > -1) {
		close(fd);
	}
	free(info);
	return r;
}

static int do_register(int argc, char *argv[])
{
	int r = EXIT_SUCCESS;
	struct powertcp_bpf *skel;
	struct bpf_link *link = NULL;
	int map_fd = -1;
	struct bpf_map *map_tcp_int_state = NULL;

	skel = powertcp_bpf__open();
	if (!skel) {
		perror("open");
		return EXIT_FAILURE;
	}

	for (int i = 0; i < argc; ++i) {
		if (parse_param(argv[i], skel->rodata)) {
			r = EXIT_FAILURE;
			goto fail;
		}
	}

	map_fd = bpf_obj_get(TCP_INT_BPF_PIN_PATH "/map_tcp_int_state");
	if (map_fd < 0) {
		perror("obj_get(map_tcp_int_state)");
		r = EXIT_FAILURE;
		goto fail;
	}

	map_tcp_int_state =
		bpf_object__find_map_by_name(skel->obj, "map_tcp_int_state");
	if (!map_tcp_int_state) {
		perror("find_map_by_name(map_tcp_int_state)");
		r = EXIT_FAILURE;
		goto fail;
	}

	if (bpf_map__reuse_fd(map_tcp_int_state, map_fd) < 0) {
		perror("reuse_fd(map_tcp_int_state)");
		r = EXIT_FAILURE;
		goto fail;
	}

	if (powertcp_bpf__load(skel)) {
		perror("load");
		r = EXIT_FAILURE;
		goto fail;
	}

	if (attach_struct_ops(skel->maps.powertcp)) {
		r = EXIT_FAILURE;
		goto fail;
	}

	if (attach_struct_ops(skel->maps.rttpowertcp)) {
		r = EXIT_FAILURE;
		goto fail;
	}

fail:
	if (map_fd > -1) {
		close(map_fd);
	}
	bpf_link__destroy(link);
	powertcp_bpf__destroy(skel);

	return r;
}

static int do_unregister(void)
{
	int r = EXIT_SUCCESS;
	if (delete_struct_ops("powertcp")) {
		r = EXIT_FAILURE;
	}
	if (delete_struct_ops("rttpowertcp")) {
		r = EXIT_FAILURE;
	}
	return r;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %1$s register|unregister [PARAMETER...]\n"
		"\n"
		"PARAMETERS\n"
		"   The following parameters of the PowerTCP algorithm can be set with the\n"
		"   register command:\n"
		"    - base_rtt in µs\n"
		"    - beta in number of packets\n"
		"    - expected_flows\n"
		"    - gamma\n"
		"    - hop_bw in Mbit/s\n"
		"    - host_bw in Mbit/s\n"
		"\n"
		"EXAMPLE\n"
		"\n"
		"   $ %1$s register expected_flows=1\n"
		"\n",
		prog);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (0 == strcmp("register", argv[1])) {
		return do_register(argc - 2, argv + 2);
	} else if (0 == strcmp("unregister", argv[1])) {
		if (argc > 2) {
			fprintf(stderr,
				"unexpected argument(s) after 'unregister'\n");
			return EXIT_FAILURE;
		}
		return do_unregister();
	}

	usage(argv[0]);
	return EXIT_FAILURE;
}
