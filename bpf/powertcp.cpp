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

#include <cassert>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <linux/bpf.h>
#include <linux/types.h>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <variant>

namespace
{
struct powertcp_param_double {
	std::size_t rodata_off;
	double scale;
};

struct powertcp_param_long {
	std::size_t rodata_off;
};

using powertcp_param = std::variant<powertcp_param_double, powertcp_param_long>;

struct powertcp_param_visitor {
	const std::string &str;

	long operator()(const powertcp_param_double &par) const
	{
		return std::stod(str) * par.scale;
	}

	long operator()(const powertcp_param_long &) const
	{
		return std::stol(str);
	}
};

class unique_fd {
    public:
	unique_fd() noexcept : fd_{ -1 }
	{
	}

	explicit unique_fd(int fd) noexcept : fd_{ fd }
	{
	}

	unique_fd(const unique_fd &) = delete;
	unique_fd &operator=(const unique_fd &) = delete;

	unique_fd(unique_fd &&other) noexcept
		: fd_{ std::exchange(other.fd_, -1) }
	{
	}

	unique_fd &operator=(unique_fd &&other) noexcept
	{
		close();
		std::swap(fd_, other.fd_);
		return *this;
	}

	~unique_fd()
	{
		close();
	}

	explicit operator bool() const noexcept
	{
		return fd_ > -1;
	}

	void close() noexcept
	{
		if (fd_ > -1) {
			::close(fd_); /* Ignoring any errors here. */
			fd_ = -1;
		}
	}

	int get() const noexcept
	{
		return fd_;
	}

    private:
	int fd_;
};

#define POWERTCP_RODATA_OFFSET(member)                                         \
	offsetof(powertcp_bpf::powertcp_bpf__rodata, member)
const std::unordered_map<std::string, powertcp_param> params = {
	{ "base_rtt", powertcp_param_long{ POWERTCP_RODATA_OFFSET(base_rtt) } },
	{ "beta",
	  powertcp_param_double{ POWERTCP_RODATA_OFFSET(beta), cwnd_scale } },
	{ "expected_flows",
	  powertcp_param_long{ POWERTCP_RODATA_OFFSET(expected_flows) } },
	{ "gamma",
	  powertcp_param_double{ POWERTCP_RODATA_OFFSET(gamma), gamma_scale } },
	{ "hop_bw", powertcp_param_long{ POWERTCP_RODATA_OFFSET(hop_bw) } },
	{ "host_bw", powertcp_param_long{ POWERTCP_RODATA_OFFSET(host_bw) } },
};
#undef POWERTCP_RODATA_OFFSET

void parse_param(std::string param_arg,
		 powertcp_bpf::powertcp_bpf__rodata *rodata)
{
	std::istringstream iss(std::move(param_arg));

	std::string name_tok;
	std::getline(iss, name_tok, '=');

	const auto param_iter = params.find(name_tok);
	if (param_iter == std::end(params)) {
		std::ostringstream oss;
		oss << "Unknown algorithm parameter '" << name_tok << "'";
		throw std::invalid_argument(oss.str());
	}

	std::string value_tok;
	std::getline(iss, value_tok, '=');

	long val;
	try {
		val = std::visit(powertcp_param_visitor{ value_tok },
				 param_iter->second);
	} catch (const std::invalid_argument &) {
		std::ostringstream oss;
		oss << "Invalid value '" << value_tok << "' for parameter "
		    << name_tok << ": invalid number";
		throw std::invalid_argument(oss.str());
	} catch (const std::out_of_range &) {
		std::ostringstream oss;
		oss << "Invalid value '" << value_tok << "' for parameter "
		    << name_tok << ": out of range";
		throw std::out_of_range(oss.str());
	}

	assert(rodata != nullptr);
	std::size_t rodata_off = std::visit(
		[](auto &&p) { return p.rodata_off; }, param_iter->second);
	long *rodata_param = reinterpret_cast<long *>(
		reinterpret_cast<char *>(rodata) + rodata_off);
	/* TODO: Maybe check if a value is in the allowed range. Or do that in the
	 * BPF code.
	 */
	*rodata_param = val;
}

void attach_struct_ops(bpf_map *struct_ops)
{
	bpf_link *link = bpf_map__attach_struct_ops(struct_ops);
	if (libbpf_get_error(link)) {
		if (errno == EEXIST) {
			fprintf(stderr, "%s is already registered, skipping\n",
				bpf_map__name(struct_ops));
			return;
		}

		std::ostringstream oss;
		oss << "attach_struct_ops(" << bpf_map__name(struct_ops)
		    << "): " << strerror(errno);
		throw std::system_error(errno, std::generic_category(),
					oss.str());
	}

	/* Have to __disconnect() before __destroy() so the attached struct_ops
	 * outlive this userspace program.
	 */
	bpf_link__disconnect(link);
	bpf_link__destroy(link);
}

void delete_struct_ops(const char *map_name)
{
	unique_fd fd;
	__u32 id = 0;

	auto info = bpf_map_info{};
	__u32 info_len = sizeof(info);

	while (true) {
		if (bpf_map_get_next_id(id, &id)) {
			if (errno != ENOENT) {
				throw std::system_error(errno,
							std::generic_category(),
							"map_get_next_id");
			}
			return;
		}

		fd = unique_fd(bpf_map_get_fd_by_id(id));
		if (!fd) {
			if (errno == ENOENT) {
				continue;
			}
			throw std::system_error(errno, std::generic_category(),
						"map_get_fd_by_id");
		}

		if (bpf_obj_get_info_by_fd(fd.get(), &info, &info_len)) {
			throw std::system_error(errno, std::generic_category(),
						"obj_get_info_by_fd");
		}

		if (info.type == BPF_MAP_TYPE_STRUCT_OPS &&
		    0 == strcmp(map_name, info.name)) {
			break;
		}
	}

	constexpr auto zero = 0;
	if (bpf_map_delete_elem(fd.get(), &zero)) {
		throw std::system_error(errno, std::generic_category(),
					"map_delete_elem");
	}
}

void do_register(int argc, char *argv[])
{
	auto skel = std::unique_ptr<powertcp_bpf, void (*)(powertcp_bpf *)>(
		powertcp_bpf__open(), powertcp_bpf__destroy);
	if (!skel) {
		throw std::system_error(errno, std::generic_category(), "open");
	}

	for (int i = 0; i < argc; ++i) {
		parse_param(argv[i], skel->rodata);
	}

	auto map_fd = unique_fd(
		bpf_obj_get(TCP_INT_BPF_PIN_PATH "/map_tcp_int_state"));
	if (!map_fd) {
		throw std::system_error(errno, std::generic_category(),
					"obj_get(map_tcp_int_state)");
	}

	auto *map_tcp_int_state =
		bpf_object__find_map_by_name(skel->obj, "map_tcp_int_state");
	if (!map_tcp_int_state) {
		throw std::system_error(errno, std::generic_category(),
					"find_map_by_name(map_tcp_int_state)");
	}

	if (bpf_map__reuse_fd(map_tcp_int_state, map_fd.get()) < 0) {
		throw std::system_error(errno, std::generic_category(),
					"reuse_fd(map_tcp_int_state)");
	}

	if (powertcp_bpf__load(skel.get())) {
		throw std::system_error(errno, std::generic_category(), "load");
	}

	attach_struct_ops(skel->maps.powertcp);
	attach_struct_ops(skel->maps.rttpowertcp);
}

void do_unregister(void)
{
	delete_struct_ops("powertcp");
	delete_struct_ops("rttpowertcp");
}

void usage(const char *prog, FILE *outfile)
{
	fprintf(outfile,
		"Usage: %1$s [OPTION...] register [PARAMETER...]\n"
		"       %1$s unregister\n"
		"\n"
		"COMMANDS\n"
		"   register\n"
		"      Register the PowerTCP eBPF programs, optionally setting algorithm\n"
		"      parameters.\n"
		"\n"
		"   unregister\n"
		"      Unregister the PowerTCP eBPF programs.\n"
		"\n"
		"OPTIONS\n"
		"   -f\n"
		"      Force an unregister before a register so parameters can be set to\n"
		"      new values.\n"
		"\n"
		"PARAMETERS\n"
		"   The following parameters of the PowerTCP algorithm can be set with the\n"
		"   register command:\n"
		"    - base_rtt in µs\n"
		"    - beta in number of packets\n"
		"    - expected_flows in number of flows\n"
		"    - gamma in range 0.0 to 1.0\n"
		"    - hop_bw in Mbit/s\n"
		"    - host_bw in Mbit/s\n"
		"\n"
		"EXAMPLE\n"
		"\n"
		"   # %1$s register expected_flows=1\n"
		"\n",
		prog);
}
} // namespace

int main(int argc, char *argv[])
{
	bool force = false;

	int opt;
	while (-1 != (opt = getopt(argc, argv, "fh"))) {
		switch (opt) {
		case 'f':
			force = true;
			break;
		case 'h':
			usage(argv[0], stdout);
			return EXIT_SUCCESS;
		default:
			usage(argv[0], stderr);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		usage(argv[0], stderr);
		return EXIT_FAILURE;
	}

	if (0 == strcmp("register", argv[optind])) {
		if (force) {
			try {
				do_unregister();
			} catch (const std::exception &e) {
				fprintf(stderr, "%s\n", e.what());
			}
		}

		try {
			do_register(argc - optind - 1, argv + optind + 1);
		} catch (const std::exception &e) {
			fprintf(stderr, "%s\n", e.what());
		}
	} else if (0 == strcmp("unregister", argv[optind])) {
		if (argc - optind > 2) {
			fprintf(stderr,
				"unexpected argument(s) after 'unregister'\n");
			return EXIT_FAILURE;
		}
		try {
			do_unregister();
		} catch (const std::exception &e) {
			fprintf(stderr, "%s\n", e.what());
		}
	} else {
		usage(argv[0], stderr);
		return EXIT_FAILURE;
	}
}
