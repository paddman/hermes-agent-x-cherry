#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace cherry::pcap {

// Common libpcap DLT values. Kept here so the packet parser can be unit-tested
// without linking libpcap. main.cpp passes pcap_datalink() directly.
inline constexpr int kDltNull = 0;
inline constexpr int kDltEthernet = 1;
inline constexpr int kDltRaw = 12;
inline constexpr int kLinktypeRaw = 101;
inline constexpr int kDltLinuxSll = 113;
inline constexpr int kDltLinuxSll2 = 276;

enum class ParseStatus {
    ok,
    non_ip,
    unsupported_link,
    truncated,
    malformed,
};

struct PacketInfo {
    ParseStatus status{ParseStatus::malformed};
    std::string status_detail;
    std::string network_protocol;
    std::string transport_protocol;
    std::string source_ip;
    std::string destination_ip;
    std::uint16_t source_port{0};
    std::uint16_t destination_port{0};
    std::uint64_t captured_length{0};
    std::uint64_t wire_length{0};
    bool has_ports{false};
    bool fragmented{false};
    bool tcp_syn{false};
    bool tcp_ack{false};
    bool tcp_rst{false};
    bool tcp_fin{false};
    std::optional<std::string> dns_query;
    std::optional<std::uint16_t> dns_query_type;
};

struct Counter {
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
};

struct RankedCounter {
    std::string key;
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
};

struct RankedValue {
    std::string key;
    std::uint64_t count{0};
};

struct FlowRecord {
    std::string source_ip;
    std::string destination_ip;
    std::string protocol;
    std::uint16_t source_port{0};
    std::uint16_t destination_port{0};
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
    std::uint64_t tcp_syn_packets{0};
    std::uint64_t tcp_rst_packets{0};
    double first_timestamp{0.0};
    double last_timestamp{0.0};
};

struct Alert {
    std::string severity;
    std::string type;
    std::string source;
    std::string message;
    std::uint64_t evidence_count{0};
};

struct Summary {
    std::uint64_t total_packets{0};
    std::uint64_t total_captured_bytes{0};
    std::uint64_t total_wire_bytes{0};
    std::uint64_t parsed_packets{0};
    std::uint64_t non_ip_packets{0};
    std::uint64_t truncated_packets{0};
    std::uint64_t malformed_packets{0};
    std::uint64_t unsupported_link_packets{0};
    std::uint64_t fragmented_packets{0};
    std::uint64_t dns_queries{0};
    std::uint64_t dropped_new_flows{0};
};

class PacketParser {
public:
    [[nodiscard]] static PacketInfo parse(
        int link_type,
        const std::uint8_t* data,
        std::size_t captured_length,
        std::size_t wire_length);
};

class Analyzer {
public:
    struct Config {
        std::size_t max_flows{200'000};
        std::uint32_t syn_scan_threshold{20};
        std::uint32_t dns_query_threshold{100};
    };

    Analyzer();
    explicit Analyzer(Config config);

    void consume(const PacketInfo& packet, double timestamp_seconds);

    [[nodiscard]] const Summary& summary() const noexcept;
    [[nodiscard]] std::vector<RankedCounter> protocol_counters() const;
    [[nodiscard]] std::vector<RankedCounter> top_sources(std::size_t limit) const;
    [[nodiscard]] std::vector<RankedCounter> top_destinations(std::size_t limit) const;
    [[nodiscard]] std::vector<RankedCounter> top_destination_ports(std::size_t limit) const;
    [[nodiscard]] std::vector<RankedValue> top_dns_queries(std::size_t limit) const;
    [[nodiscard]] std::vector<FlowRecord> top_flows(std::size_t limit) const;
    [[nodiscard]] std::vector<Alert> alerts() const;

private:
    struct FlowKey {
        std::string source_ip;
        std::string destination_ip;
        std::string protocol;
        std::uint16_t source_port{0};
        std::uint16_t destination_port{0};

        bool operator==(const FlowKey& other) const noexcept;
    };

    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& key) const noexcept;
    };

    struct FlowStats {
        std::uint64_t packets{0};
        std::uint64_t bytes{0};
        std::uint64_t tcp_syn_packets{0};
        std::uint64_t tcp_rst_packets{0};
        double first_timestamp{0.0};
        double last_timestamp{0.0};
    };

    Config config_;
    Summary summary_;
    std::unordered_map<std::string, Counter> protocols_;
    std::unordered_map<std::string, Counter> sources_;
    std::unordered_map<std::string, Counter> destinations_;
    std::unordered_map<std::string, Counter> destination_ports_;
    std::unordered_map<std::string, std::uint64_t> dns_queries_;
    std::unordered_map<std::string, std::uint64_t> dns_queries_by_source_;
    std::unordered_map<std::string, std::unordered_set<std::string>> syn_targets_by_source_;
    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flows_;
};

[[nodiscard]] std::string parse_status_name(ParseStatus status);
[[nodiscard]] std::string json_escape(std::string_view value);

}  // namespace cherry::pcap
