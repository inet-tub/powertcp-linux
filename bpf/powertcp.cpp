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
#include <csignal>
#include <filesystem>
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
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <variant>

#include "powertcp_trace.h"

namespace
{
template <typename T, typename R, R (*DeleteFunc)(T *)>
struct delete_func_wrapper {
	void operator()(T *ptr) const noexcept
	{
		DeleteFunc(ptr);
	}
};

template <typename T, void (*DeleteFunc)(T *)>
using ptr_with_delete_func =
	std::unique_ptr<T, delete_func_wrapper<T, void, DeleteFunc> >;

using powertcp_bpf_ptr =
	ptr_with_delete_func<powertcp_bpf, powertcp_bpf__destroy>;

struct powertcp_param_bool {
	using rodata_type = bool;
	std::size_t rodata_off;
};

struct powertcp_param_double {
	using rodata_type = long;
	std::size_t rodata_off;
	double scale;
};

struct powertcp_param_long {
	using rodata_type = long;
	std::size_t rodata_off;
};

using powertcp_param = std::variant<powertcp_param_bool, powertcp_param_double,
				    powertcp_param_long>;

struct powertcp_param_visitor {
	const std::string &str;
	powertcp_bpf::powertcp_bpf__rodata *rodata;

	void operator()(const powertcp_param_bool &par) const
	{
		assign_param(true, par, rodata);
	}

	void operator()(const powertcp_param_double &par) const
	{
		assign_param(std::stod(str) * par.scale, par, rodata);
	}

	void operator()(const powertcp_param_long &par) const
	{
		assign_param(std::stol(str), par, rodata);
	}

	template <typename T, typename P>
	void assign_param(T val, P param,
			  powertcp_bpf::powertcp_bpf__rodata *rodata) const
	{
		assert(rodata != nullptr);

		auto &rodata_param =
			*reinterpret_cast<typename P::rodata_type *>(
				reinterpret_cast<char *>(rodata) +
				param.rodata_off);
		/* TODO: Maybe check if a value is in the allowed range. Or do that in
		 * the BPF code. */
		rodata_param = val;
	}
};

using ring_buffer_ptr = ptr_with_delete_func<ring_buffer, ring_buffer__free>;

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

using bpf_link_ptr =
	std::unique_ptr<bpf_link,
			delete_func_wrapper<bpf_link, int, bpf_link__destroy> >;

#define POWERTCP_RODATA_OFFSET(member)                                         \
	offsetof(powertcp_bpf::powertcp_bpf__rodata, member)
const std::unordered_map<std::string, powertcp_param> params = {
	{ "base_rtt", powertcp_param_long{ POWERTCP_RODATA_OFFSET(base_rtt) } },
	{ "beta", powertcp_param_long{ POWERTCP_RODATA_OFFSET(beta) } },
	{ "expected_flows",
	  powertcp_param_long{ POWERTCP_RODATA_OFFSET(expected_flows) } },
	{ "gamma",
	  powertcp_param_double{ POWERTCP_RODATA_OFFSET(gamma), gamma_scale } },
	{ "hop_bw", powertcp_param_long{ POWERTCP_RODATA_OFFSET(hop_bw) } },
	{ "host_bw", powertcp_param_long{ POWERTCP_RODATA_OFFSET(host_bw) } },
	{ "tracing", powertcp_param_bool{ POWERTCP_RODATA_OFFSET(tracing) } },
};
#undef POWERTCP_RODATA_OFFSET

const std::filesystem::path powertcp_pin_dir = "/sys/fs/bpf/powertcp";

volatile std::sig_atomic_t running = true;

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

	try {
		std::visit(powertcp_param_visitor{ value_tok, rodata },
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
}

void pin_map(bpf_map *map)
{
	assert(map != nullptr);

	const char *map_name = bpf_map__name(map);
	const auto pin_path = powertcp_pin_dir / map_name;
	if (bpf_map__pin(map, pin_path.c_str())) {
		std::ostringstream oss;
		oss << "bpf_map__pin(" << map_name << ")";
		throw std::system_error(errno, std::generic_category(),
					oss.str());
	}
}

void attach_struct_ops(bpf_map *struct_ops)
{
	auto link = bpf_link_ptr{ bpf_map__attach_struct_ops(struct_ops) };
	if (!link) {
		if (errno == EEXIST) {
			fprintf(stderr, "%s is already registered, skipping\n",
				bpf_map__name(struct_ops));
			return;
		}

		std::ostringstream oss;
		oss << "attach_struct_ops(" << bpf_map__name(struct_ops) << ")";
		throw std::system_error(errno, std::generic_category(),
					oss.str());
	}

	/* Have to __disconnect() before __destroy() so the attached struct_ops
	 * outlive this userspace program.
	 */
	bpf_link__disconnect(link.get());
}

void delete_struct_ops(std::string_view map_name)
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
		    map_name == info.name) {
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
	auto skel = powertcp_bpf_ptr{ powertcp_bpf__open() };
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

	/* struct_ops program maps are "pinned"/kept alive in their own way (see
	 * the comment in attach_struct_ops()), we only want to pin other maps
	 * here:
	 */
	pin_map(skel->maps.trace_events);
}

int handle_trace_event(void * /* ctx */, void *data, std::size_t /* data_sz */)
{
	/* TODO: If it seems appropriate later, merge handle_trace_event() and
	 * handle_trace_event_csv() and just use two different format strings.
	 */
	const powertcp_trace_event &ev =
		*static_cast<powertcp_trace_event *>(data);

	/*
	 * Desired alignment in the output, showing the maximum value per data type:
	 *
	 * # Time (us)           Socket hash  CWND (segments)  Pacing rate (Mbit/s)  Norm. power  Smoothed power  Queue length (bytes)  Delta t (ns)  Tx. bytes diff
	 * 18446744073709551615   4294967295       4294967295            xxxxxxxxxx   x.yyyyyyyy      x.yyyyyyyy            4294967295    4294967295      4294967295
	 */
	std::printf(
		"%20llu   %10u       %10u            %10lu   %10.8f      %10.8f            %10ld    %10u      %10u\n",
		ev.time, ev.sock_hash, ev.cwnd, ev.rate * 8 / 1000000,
		static_cast<double>(ev.p_norm) / power_scale,
		static_cast<double>(ev.p_smooth) / power_scale, ev.qlen,
		ev.delta_t, ev.tx_bytes_diff);

	return 0;
}

int handle_trace_event_csv(void * /* ctx */, void *data,
			   std::size_t /* data_sz */)
{
	/* TODO: If it seems appropriate later, merge handle_trace_event() and
	 * handle_trace_event_csv() and just use two different format strings.
	 */
	const auto &ev = *static_cast<powertcp_trace_event *>(data);

	std::printf("%llu,%u,%u,%lu,%0f,%0f,%ld,%u,%u\n", ev.time, ev.sock_hash,
		    ev.cwnd, ev.rate,
		    static_cast<double>(ev.p_norm) / power_scale,
		    static_cast<double>(ev.p_smooth) / power_scale, ev.qlen,
		    ev.delta_t, ev.tx_bytes_diff);

	return 0;
}

void do_trace(bool output_csv)
{
	auto map_fd = unique_fd{ bpf_obj_get(
		(powertcp_pin_dir / "trace_events").c_str()) };
	if (!map_fd) {
		throw std::system_error(-map_fd.get(), std::generic_category(),
					"bpf_obj_get");
	}

	auto handle_func =
		output_csv ? handle_trace_event_csv : handle_trace_event;
	auto ring_buf = ring_buffer_ptr{ ring_buffer__new(
		map_fd.get(), handle_func, nullptr, nullptr) };
	if (!ring_buf) {
		throw std::system_error(errno, std::generic_category(),
					"ring_buffer__new");
	}

	if (output_csv) {
		std::printf(
			"time,hash,cwnd,rate,p_norm,p_smooth,qlen,delta_t,tx_bytes_diff\n");
	} else {
		std::printf(
			"# Time (us)           Socket hash  CWND (segments)  Pacing rate (Mbit/s)  Norm. power  Smoothed power  Queue length (bytes)  Delta t (ns)  Tx. bytes diff\n");
	}

	while (running) {
		if (auto err = ring_buffer__poll(ring_buf.get(), 100);
		    err < 0 && err != -EINTR) {
			throw std::system_error(-err, std::generic_category(),
						"ring_buffer__poll");
		} else if (err == 0) {
			std::fflush(stdout); /* Flush on timeout */
		}
	}
}

void do_unregister()
{
	delete_struct_ops("powertcp");
	delete_struct_ops("rttpowertcp");
	std::filesystem::remove_all(powertcp_pin_dir);
}

void handle_signal(int /* sig */)
{
	running = false;
}

void usage(const char *prog, FILE *outfile)
{
	fprintf(outfile,
		"Usage: %1$s [OPTION...] register [PARAMETER...]\n"
		"       %1$s [OPTION...] trace | unregister\n"
		"\n"
		"COMMANDS\n"
		"   register\n"
		"      Register the PowerTCP eBPF programs, optionally setting algorithm\n"
		"      parameters.\n"
		"\n"
		"   trace\n"
		"      Trace the execution of the algorithm.\n"
		"\n"
		"   unregister\n"
		"      Unregister the PowerTCP eBPF programs.\n"
		"\n"
		"OPTIONS\n"
		"   -C\n"
		"      Output traced values in CSV format.\n"
		"\n"
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
		"   Passing the additional, value-less parameter \"tracing\" enables tracing\n"
		"   the algorithm with trace command.\n"
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
	auto output_csv = false;

	int opt;
	while (-1 != (opt = getopt(argc, argv, "Cfh"))) {
		switch (opt) {
		case 'C':
			output_csv = true;
			break;
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

	struct sigaction sigact = {};
	sigact.sa_handler = handle_signal;
	sigact.sa_flags = SA_RESETHAND;
	if (sigaction(SIGINT, &sigact, nullptr)) {
		std::perror("sigaction");
		return EXIT_FAILURE;
	}

	const auto cmd = std::string_view{ argv[optind] };
	if (cmd == "register") {
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
	} else if (cmd == "trace") {
		try {
			do_trace(output_csv);
		} catch (const std::exception &e) {
			fprintf(stderr, "%s\n", e.what());
		}
	} else if (cmd == "unregister") {
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
