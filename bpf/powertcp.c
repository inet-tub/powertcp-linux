// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Loader and configuration tool for the eBPF implementation of the PowerTCP
 * congestion control algorithm.
 *
 * Author:
 *   Jörn-Thorben Hinz, TU Berlin, 2022.
 */
#include "powertcp.skel.h"

#include "tcp_int.h"

#include <bpf/bpf.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

static int do_register(void)
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

	link = bpf_map__attach_struct_ops(skel->maps.powertcp);
	if (libbpf_get_error(link)) {
		perror("attach_struct_ops");
		r = EXIT_FAILURE;
		goto fail;
	}

	/* Have to __disconnect() before __destroy() so the attached struct_ops
	 * outlive this userspace program.
	 */
	bpf_link__disconnect(link);

fail:
	if (map_fd > -1) {
		close(map_fd);
	}
	bpf_link__destroy(link); /* Save to call with an error value. */
	powertcp_bpf__destroy(skel);

	return r;
}

static int do_unregister(void)
{
	int r = EXIT_SUCCESS;
	int fd = -1;
	__u32 id = 0;
	struct bpf_map_info *info;
	__u32 info_len = sizeof(*info);
	const int zero = 0;

	info = calloc(1, info_len);
	if (!info) {
		perror("calloc");
		return EXIT_FAILURE;
	}

	while (true) {
		if (bpf_map_get_next_id(id, &id)) {
			if (errno != ENOENT) {
				perror("map_get_next_id");
				r = EXIT_FAILURE;
			}
			goto fail;
		}

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT) {
				continue;
			}
			perror("map_get_fd_by_id");
			r = EXIT_FAILURE;
			goto fail;
		}

		if (bpf_obj_get_info_by_fd(fd, info, &info_len)) {
			perror("obj_get_info_by_fd");
			r = EXIT_FAILURE;
			goto fail;
		}

		if (info->type == BPF_MAP_TYPE_STRUCT_OPS &&
		    0 == strcmp("powertcp", info->name)) {
			break;
		}

		close(fd);
		fd = -1;
	}

	if (bpf_map_delete_elem(fd, &zero)) {
		perror("map_delete_elem");
		r = EXIT_FAILURE;
	}

fail:
	if (fd > -1) {
		close(fd);
	}
	free(info);
	return r;
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s register|unregister\n", prog);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if (0 == strcmp("register", argv[1])) {
		return do_register();
	} else if (0 == strcmp("unregister", argv[1])) {
		return do_unregister();
	}

	usage(argv[0]);
	return EXIT_FAILURE;
}
