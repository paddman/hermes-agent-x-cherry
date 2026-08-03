#include "cherry_pcap/analyzer.hpp"

#if __has_include(<pcap/pcap.h>)
#include <pcap/pcap.h>
#elif __has_include(<pcap.h>)
#include <pcap.h>
#else
#error "libpcap/Npcap headers were not found"
#endif

#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

namespace {

using cherry::pcap::Alert;
using cherry::pcap::Analyzer;
using cherry::pcap::FlowRecord;
using cherry::pcap::RankedCounter;
using cherry::pcap::RankedValue;
using cherry::pcap::Summary;

volatile std::sig_atomic_t g_stop_requested = 0;

void handle_signal(int) {
    g_stop_requested = 1;
}

struct Options {
    std::string input_file;
    std::string interface_name;
    std::string bpf_filter;
    std::string output_path{"-"};
    bool list_interfaces{false};
    bool pretty{false};
    bool promiscuous{false};
    std::uint64_t packet_limit{0};
    double duration_seconds{0.0};
    std::size_t top_count{20};
    std::size_t flow_count{25};
    std::size_t max_flows{200'000};
    std::uint32_t scan_threshold{20};
    std::uint32_t dns_threshold{100};
    int snap_length{262'144};
    int read_timeout_ms{500};
};

struct CaptureMetadata {
    std::string mode;
    std::string source;
    std::string bpf_filter;
    int datalink_value{0};
    std::string datalink_name;
    std::uint64_t packets_seen{0};
    std::optional<double> first_packet_epoch;
    std::optional<double> last_packet_epoch;
    double elapsed_wall_seconds{0.0};
};

struct PcapCloser {
    void operator()(pcap_t* handle) const noexcept {
        if (handle != nullptr) {
            pcap_close(handle);
        }
    }
};

using PcapHandle = std::unique_ptr<pcap_t, PcapCloser>;

[[noreturn]] void usage_error(const std::string& message) {
    throw std::invalid_argument(message + "\nRun cherry-pcap --help for usage.");
}

void print_help(std::ostream& out) {
    out << R"HELP(Cherry PCAP C++ analyzer

Usage:
  cherry-pcap --file CAPTURE.pcap [options]
  cherry-pcap --interface NAME [options]
  cherry-pcap --list-interfaces [--pretty]

Input:
  --file PATH                 Read a PCAP/PCAPNG file through libpcap
  --interface NAME            Capture from a live interface
  --list-interfaces           List interfaces visible to libpcap/Npcap
  --filter EXPR               Apply a BPF capture filter, e.g. "tcp or udp port 53"
  --promiscuous               Enable promiscuous mode for live capture
  --snaplen BYTES             Live capture snapshot length (default: 262144)
  --read-timeout-ms MS        Live capture read timeout (default: 500)

Limits and output:
  --limit N                   Stop after N packets; 0 means unlimited
  --duration SECONDS          Stop live capture after wall-clock seconds
  --output PATH               Write JSON to PATH; default is stdout (-)
  --pretty                    Pretty-print JSON
  --top N                     Number of top talkers/ports/DNS names (default: 20)
  --flows N                   Number of top flows in output (default: 25)
  --max-flows N               Maximum distinct flows retained (default: 200000)

Heuristics:
  --scan-threshold N          Alert after N unique SYN targets; 0 disables
  --dns-threshold N           Alert after N DNS queries per source; 0 disables

Examples:
  cherry-pcap --file incident.pcap --pretty --output report.json
  cherry-pcap --file huge.pcapng --filter "tcp or udp port 53" --limit 500000
  sudo cherry-pcap --interface eth0 --duration 60 --promiscuous --pretty
)HELP";
}

template <typename T>
T parse_unsigned(std::string_view text, const std::string& option_name) {
    static_assert(std::is_unsigned_v<T>, "parse_unsigned requires an unsigned type");
    if (text.empty()) {
        usage_error(option_name + " requires a value");
    }
    unsigned long long parsed = 0;
    const char* begin = text.data();
    const char* end = text.data() + text.size();
    const auto [ptr, error] = std::from_chars(begin, end, parsed);
    if (error != std::errc{} || ptr != end || parsed > std::numeric_limits<T>::max()) {
        usage_error(option_name + " has an invalid numeric value: " + std::string(text));
    }
    return static_cast<T>(parsed);
}

int parse_nonnegative_int(std::string_view text, const std::string& option_name) {
    return static_cast<int>(parse_unsigned<unsigned int>(text, option_name));
}

double parse_nonnegative_double(std::string_view text, const std::string& option_name) {
    try {
        std::size_t consumed = 0;
        const double value = std::stod(std::string(text), &consumed);
        if (consumed != text.size() || value < 0.0 || !std::isfinite(value)) {
            usage_error(option_name + " has an invalid numeric value: " + std::string(text));
        }
        return value;
    } catch (const std::exception&) {
        usage_error(option_name + " has an invalid numeric value: " + std::string(text));
    }
}

Options parse_arguments(int argc, char** argv) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        const auto value = [&](const std::string& name) -> std::string {
            if (index + 1 >= argc) {
                usage_error(name + " requires a value");
            }
            ++index;
            return argv[index];
        };

        if (argument == "--help" || argument == "-h") {
            print_help(std::cout);
            std::exit(0);
        } else if (argument == "--file") {
            options.input_file = value(argument);
        } else if (argument == "--interface") {
            options.interface_name = value(argument);
        } else if (argument == "--list-interfaces") {
            options.list_interfaces = true;
        } else if (argument == "--filter") {
            options.bpf_filter = value(argument);
        } else if (argument == "--output") {
            options.output_path = value(argument);
        } else if (argument == "--limit") {
            options.packet_limit = parse_unsigned<std::uint64_t>(value(argument), argument);
        } else if (argument == "--duration") {
            options.duration_seconds = parse_nonnegative_double(value(argument), argument);
        } else if (argument == "--top") {
            options.top_count = parse_unsigned<std::size_t>(value(argument), argument);
        } else if (argument == "--flows") {
            options.flow_count = parse_unsigned<std::size_t>(value(argument), argument);
        } else if (argument == "--max-flows") {
            options.max_flows = parse_unsigned<std::size_t>(value(argument), argument);
        } else if (argument == "--scan-threshold") {
            options.scan_threshold = parse_unsigned<std::uint32_t>(value(argument), argument);
        } else if (argument == "--dns-threshold") {
            options.dns_threshold = parse_unsigned<std::uint32_t>(value(argument), argument);
        } else if (argument == "--snaplen") {
            options.snap_length = parse_nonnegative_int(value(argument), argument);
        } else if (argument == "--read-timeout-ms") {
            options.read_timeout_ms = parse_nonnegative_int(value(argument), argument);
        } else if (argument == "--pretty") {
            options.pretty = true;
        } else if (argument == "--promiscuous") {
            options.promiscuous = true;
        } else {
            usage_error("unknown option: " + argument);
        }
    }

    const int input_modes = static_cast<int>(!options.input_file.empty()) +
                            static_cast<int>(!options.interface_name.empty()) +
                            static_cast<int>(options.list_interfaces);
    if (input_modes != 1) {
        usage_error("choose exactly one of --file, --interface, or --list-interfaces");
    }
    if (!options.interface_name.empty() && options.snap_length <= 0) {
        usage_error("--snaplen must be greater than zero");
    }
    if (options.max_flows == 0U) {
        usage_error("--max-flows must be greater than zero");
    }
    if (options.duration_seconds > 0.0 && options.interface_name.empty()) {
        usage_error("--duration is supported only with --interface");
    }
    return options;
}

void newline_and_indent(std::ostream& out, bool pretty, int level) {
    if (!pretty) {
        return;
    }
    out << '\n' << std::string(static_cast<std::size_t>(level) * 2U, ' ');
}

void write_string(std::ostream& out, std::string_view value) {
    out << '"' << cherry::pcap::json_escape(value) << '"';
}

void write_counter_array(
    std::ostream& out,
    const std::vector<RankedCounter>& values,
    bool pretty,
    int level) {
    out << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        newline_and_indent(out, pretty, level + 1);
        const RankedCounter& value = values[index];
        out << '{';
        newline_and_indent(out, pretty, level + 2);
        out << "\"key\":";
        if (pretty) out << ' ';
        write_string(out, value.key);
        out << ',';
        newline_and_indent(out, pretty, level + 2);
        out << "\"packets\":";
        if (pretty) out << ' ';
        out << value.packets << ',';
        newline_and_indent(out, pretty, level + 2);
        out << "\"bytes\":";
        if (pretty) out << ' ';
        out << value.bytes;
        newline_and_indent(out, pretty, level + 1);
        out << '}';
    }
    if (!values.empty()) {
        newline_and_indent(out, pretty, level);
    }
    out << ']';
}

void write_value_array(
    std::ostream& out,
    const std::vector<RankedValue>& values,
    bool pretty,
    int level) {
    out << '[';
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        newline_and_indent(out, pretty, level + 1);
        out << '{';
        newline_and_indent(out, pretty, level + 2);
        out << "\"key\":";
        if (pretty) out << ' ';
        write_string(out, values[index].key);
        out << ',';
        newline_and_indent(out, pretty, level + 2);
        out << "\"count\":";
        if (pretty) out << ' ';
        out << values[index].count;
        newline_and_indent(out, pretty, level + 1);
        out << '}';
    }
    if (!values.empty()) {
        newline_and_indent(out, pretty, level);
    }
    out << ']';
}

void write_alert_array(
    std::ostream& out,
    const std::vector<Alert>& alerts,
    bool pretty,
    int level) {
    out << '[';
    for (std::size_t index = 0; index < alerts.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        const Alert& alert = alerts[index];
        newline_and_indent(out, pretty, level + 1);
        out << '{';
        const auto string_field = [&](const char* name, const std::string& value, bool comma) {
            newline_and_indent(out, pretty, level + 2);
            write_string(out, name);
            out << ':';
            if (pretty) out << ' ';
            write_string(out, value);
            if (comma) out << ',';
        };
        string_field("severity", alert.severity, true);
        string_field("type", alert.type, true);
        string_field("source", alert.source, true);
        string_field("message", alert.message, true);
        newline_and_indent(out, pretty, level + 2);
        out << "\"evidence_count\":";
        if (pretty) out << ' ';
        out << alert.evidence_count;
        newline_and_indent(out, pretty, level + 1);
        out << '}';
    }
    if (!alerts.empty()) {
        newline_and_indent(out, pretty, level);
    }
    out << ']';
}

void write_flow_array(
    std::ostream& out,
    const std::vector<FlowRecord>& flows,
    bool pretty,
    int level) {
    out << '[';
    for (std::size_t index = 0; index < flows.size(); ++index) {
        if (index != 0U) {
            out << ',';
        }
        const FlowRecord& flow = flows[index];
        newline_and_indent(out, pretty, level + 1);
        out << '{';
        const auto separator = [&](const char* name) {
            newline_and_indent(out, pretty, level + 2);
            write_string(out, name);
            out << ':';
            if (pretty) out << ' ';
        };
        separator("source_ip"); write_string(out, flow.source_ip); out << ',';
        separator("source_port"); out << flow.source_port << ',';
        separator("destination_ip"); write_string(out, flow.destination_ip); out << ',';
        separator("destination_port"); out << flow.destination_port << ',';
        separator("protocol"); write_string(out, flow.protocol); out << ',';
        separator("packets"); out << flow.packets << ',';
        separator("bytes"); out << flow.bytes << ',';
        separator("tcp_syn_packets"); out << flow.tcp_syn_packets << ',';
        separator("tcp_rst_packets"); out << flow.tcp_rst_packets << ',';
        separator("first_packet_epoch"); out << std::fixed << std::setprecision(6)
                                             << flow.first_timestamp << ',';
        separator("last_packet_epoch"); out << std::fixed << std::setprecision(6)
                                            << flow.last_timestamp;
        newline_and_indent(out, pretty, level + 1);
        out << '}';
    }
    if (!flows.empty()) {
        newline_and_indent(out, pretty, level);
    }
    out << ']';
}

void write_summary(std::ostream& out, const Summary& summary, bool pretty, int level) {
    out << '{';
    const auto field = [&](const char* name, std::uint64_t value, bool comma) {
        newline_and_indent(out, pretty, level + 1);
        write_string(out, name);
        out << ':';
        if (pretty) out << ' ';
        out << value;
        if (comma) out << ',';
    };
    field("total_packets", summary.total_packets, true);
    field("total_captured_bytes", summary.total_captured_bytes, true);
    field("total_wire_bytes", summary.total_wire_bytes, true);
    field("parsed_packets", summary.parsed_packets, true);
    field("non_ip_packets", summary.non_ip_packets, true);
    field("truncated_packets", summary.truncated_packets, true);
    field("malformed_packets", summary.malformed_packets, true);
    field("unsupported_link_packets", summary.unsupported_link_packets, true);
    field("fragmented_packets", summary.fragmented_packets, true);
    field("dns_queries", summary.dns_queries, true);
    field("dropped_new_flows", summary.dropped_new_flows, false);
    newline_and_indent(out, pretty, level);
    out << '}';
}

void write_report(
    std::ostream& out,
    const Options& options,
    const CaptureMetadata& capture,
    const Analyzer& analyzer) {
    const bool pretty = options.pretty;
    out << '{';

    newline_and_indent(out, pretty, 1);
    out << "\"schema_version\":";
    if (pretty) out << ' ';
    out << 1 << ',';

    newline_and_indent(out, pretty, 1);
    out << "\"engine\":";
    if (pretty) out << ' ';
    write_string(out, "cherry-pcap-cpp");
    out << ',';

    newline_and_indent(out, pretty, 1);
    out << "\"capture\":";
    if (pretty) out << ' ';
    out << '{';
    const auto capture_string = [&](const char* name, const std::string& value, bool comma) {
        newline_and_indent(out, pretty, 2);
        write_string(out, name);
        out << ':';
        if (pretty) out << ' ';
        write_string(out, value);
        if (comma) out << ',';
    };
    capture_string("mode", capture.mode, true);
    capture_string("source", capture.source, true);
    capture_string("bpf_filter", capture.bpf_filter, true);
    newline_and_indent(out, pretty, 2);
    out << "\"datalink_value\":";
    if (pretty) out << ' ';
    out << capture.datalink_value << ',';
    capture_string("datalink_name", capture.datalink_name, true);
    newline_and_indent(out, pretty, 2);
    out << "\"packets_seen\":";
    if (pretty) out << ' ';
    out << capture.packets_seen << ',';
    newline_and_indent(out, pretty, 2);
    out << "\"first_packet_epoch\":";
    if (pretty) out << ' ';
    if (capture.first_packet_epoch.has_value()) {
        out << std::fixed << std::setprecision(6) << *capture.first_packet_epoch;
    } else {
        out << "null";
    }
    out << ',';
    newline_and_indent(out, pretty, 2);
    out << "\"last_packet_epoch\":";
    if (pretty) out << ' ';
    if (capture.last_packet_epoch.has_value()) {
        out << std::fixed << std::setprecision(6) << *capture.last_packet_epoch;
    } else {
        out << "null";
    }
    out << ',';
    newline_and_indent(out, pretty, 2);
    out << "\"elapsed_wall_seconds\":";
    if (pretty) out << ' ';
    out << std::fixed << std::setprecision(3) << capture.elapsed_wall_seconds;
    newline_and_indent(out, pretty, 1);
    out << "},";

    newline_and_indent(out, pretty, 1);
    out << "\"summary\":";
    if (pretty) out << ' ';
    write_summary(out, analyzer.summary(), pretty, 1);
    out << ',';

    const auto named_array = [&](const char* name, const auto& values, const auto& writer, bool comma) {
        newline_and_indent(out, pretty, 1);
        write_string(out, name);
        out << ':';
        if (pretty) out << ' ';
        writer(out, values, pretty, 1);
        if (comma) out << ',';
    };

    named_array("protocols", analyzer.protocol_counters(), write_counter_array, true);
    named_array("top_sources", analyzer.top_sources(options.top_count), write_counter_array, true);
    named_array(
        "top_destinations",
        analyzer.top_destinations(options.top_count),
        write_counter_array,
        true);
    named_array(
        "top_destination_ports",
        analyzer.top_destination_ports(options.top_count),
        write_counter_array,
        true);
    named_array("top_dns_queries", analyzer.top_dns_queries(options.top_count), write_value_array, true);
    named_array("alerts", analyzer.alerts(), write_alert_array, true);
    named_array("top_flows", analyzer.top_flows(options.flow_count), write_flow_array, false);

    newline_and_indent(out, pretty, 0);
    out << '}';
    if (pretty) {
        out << '\n';
    }
}

void write_interfaces(const Options& options) {
    char error_buffer[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* raw_devices = nullptr;
    if (pcap_findalldevs(&raw_devices, error_buffer) != 0) {
        throw std::runtime_error(std::string("pcap_findalldevs failed: ") + error_buffer);
    }
    std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)> devices(raw_devices, pcap_freealldevs);

    std::ostream* output = &std::cout;
    std::ofstream file;
    if (options.output_path != "-") {
        const std::filesystem::path path(options.output_path);
        if (!path.parent_path().empty()) {
            std::filesystem::create_directories(path.parent_path());
        }
        file.open(path, std::ios::binary | std::ios::trunc);
        if (!file) {
            throw std::runtime_error("cannot open output file: " + options.output_path);
        }
        output = &file;
    }

    std::ostream& out = *output;
    out << '[';
    std::size_t index = 0;
    for (const pcap_if_t* device = devices.get(); device != nullptr; device = device->next) {
        if (index++ != 0U) {
            out << ',';
        }
        newline_and_indent(out, options.pretty, 1);
        out << '{';
        newline_and_indent(out, options.pretty, 2);
        out << "\"name\":";
        if (options.pretty) out << ' ';
        write_string(out, device->name == nullptr ? "" : device->name);
        out << ',';
        newline_and_indent(out, options.pretty, 2);
        out << "\"description\":";
        if (options.pretty) out << ' ';
        write_string(out, device->description == nullptr ? "" : device->description);
        out << ',';
        newline_and_indent(out, options.pretty, 2);
        out << "\"flags\":";
        if (options.pretty) out << ' ';
        out << device->flags;
        newline_and_indent(out, options.pretty, 1);
        out << '}';
    }
    if (index != 0U) {
        newline_and_indent(out, options.pretty, 0);
    }
    out << ']';
    if (options.pretty) out << '\n';
}

PcapHandle open_capture(const Options& options, CaptureMetadata& metadata) {
    char error_buffer[PCAP_ERRBUF_SIZE]{};
    pcap_t* raw_handle = nullptr;
    if (!options.input_file.empty()) {
        raw_handle = pcap_open_offline(options.input_file.c_str(), error_buffer);
        metadata.mode = "offline";
        metadata.source = options.input_file;
    } else {
        raw_handle = pcap_open_live(
            options.interface_name.c_str(),
            options.snap_length,
            options.promiscuous ? 1 : 0,
            options.read_timeout_ms,
            error_buffer);
        metadata.mode = "live";
        metadata.source = options.interface_name;
    }
    if (raw_handle == nullptr) {
        throw std::runtime_error(std::string("cannot open capture source: ") + error_buffer);
    }

    PcapHandle handle(raw_handle);
    metadata.datalink_value = pcap_datalink(handle.get());
    const char* datalink_name = pcap_datalink_val_to_name(metadata.datalink_value);
    metadata.datalink_name = datalink_name == nullptr ? "unknown" : datalink_name;
    metadata.bpf_filter = options.bpf_filter;

    if (!options.bpf_filter.empty()) {
        bpf_program program{};
        if (pcap_compile(
                handle.get(),
                &program,
                options.bpf_filter.c_str(),
                1,
                PCAP_NETMASK_UNKNOWN) != 0) {
            throw std::runtime_error(std::string("BPF compile failed: ") + pcap_geterr(handle.get()));
        }
        const int filter_result = pcap_setfilter(handle.get(), &program);
        pcap_freecode(&program);
        if (filter_result != 0) {
            throw std::runtime_error(std::string("BPF install failed: ") + pcap_geterr(handle.get()));
        }
    }
    return handle;
}

void write_output(
    const Options& options,
    const CaptureMetadata& metadata,
    const Analyzer& analyzer) {
    if (options.output_path == "-") {
        write_report(std::cout, options, metadata, analyzer);
        return;
    }

    const std::filesystem::path output_path(options.output_path);
    if (!output_path.parent_path().empty()) {
        std::filesystem::create_directories(output_path.parent_path());
    }
    std::ofstream out(output_path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + options.output_path);
    }
    write_report(out, options, metadata, analyzer);
    if (!out) {
        throw std::runtime_error("failed while writing output file: " + options.output_path);
    }
}

int run(const Options& options) {
    if (options.list_interfaces) {
        write_interfaces(options);
        return 0;
    }

    CaptureMetadata metadata;
    PcapHandle handle = open_capture(options, metadata);
    Analyzer analyzer({options.max_flows, options.scan_threshold, options.dns_threshold});

    std::signal(SIGINT, handle_signal);
#ifdef SIGTERM
    std::signal(SIGTERM, handle_signal);
#endif

    const auto wall_start = std::chrono::steady_clock::now();
    while (g_stop_requested == 0) {
        if (options.packet_limit > 0U && metadata.packets_seen >= options.packet_limit) {
            break;
        }
        if (options.duration_seconds > 0.0) {
            const double elapsed = std::chrono::duration<double>(
                std::chrono::steady_clock::now() - wall_start).count();
            if (elapsed >= options.duration_seconds) {
                break;
            }
        }

        pcap_pkthdr* header = nullptr;
        const unsigned char* data = nullptr;
        const int result = pcap_next_ex(handle.get(), &header, &data);
        if (result == 0) {
            continue;
        }
        if (result == -2) {
            break;
        }
        if (result == -1) {
            throw std::runtime_error(std::string("capture read failed: ") + pcap_geterr(handle.get()));
        }
        if (result != 1 || header == nullptr || data == nullptr) {
            continue;
        }

        const double timestamp = static_cast<double>(header->ts.tv_sec) +
                                 static_cast<double>(header->ts.tv_usec) / 1'000'000.0;
        if (!metadata.first_packet_epoch.has_value()) {
            metadata.first_packet_epoch = timestamp;
        }
        metadata.last_packet_epoch = timestamp;
        ++metadata.packets_seen;

        const auto packet = cherry::pcap::PacketParser::parse(
            metadata.datalink_value,
            reinterpret_cast<const std::uint8_t*>(data),
            header->caplen,
            header->len);
        analyzer.consume(packet, timestamp);
    }

    metadata.elapsed_wall_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - wall_start).count();
    write_output(options, metadata, analyzer);

    if (g_stop_requested != 0) {
        std::cerr << "capture interrupted; partial report written\n";
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(parse_arguments(argc, argv));
    } catch (const std::invalid_argument& error) {
        std::cerr << "argument error: " << error.what() << '\n';
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "cherry-pcap error: " << error.what() << '\n';
        return 1;
    }
}
