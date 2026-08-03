#include "cherry_pcap/analyzer.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <sstream>
#include <tuple>
#include <utility>

namespace cherry::pcap {
namespace {

constexpr std::uint16_t kEthertypeIpv4 = 0x0800;
constexpr std::uint16_t kEthertypeArp = 0x0806;
constexpr std::uint16_t kEthertypeIpv6 = 0x86DD;
constexpr std::uint16_t kEthertypeVlan = 0x8100;
constexpr std::uint16_t kEthertypeQinQ = 0x88A8;
constexpr std::uint16_t kEthertypeVlan9100 = 0x9100;

constexpr std::uint8_t kProtocolIcmp = 1;
constexpr std::uint8_t kProtocolTcp = 6;
constexpr std::uint8_t kProtocolUdp = 17;
constexpr std::uint8_t kProtocolIpv6HopByHop = 0;
constexpr std::uint8_t kProtocolIpv6Routing = 43;
constexpr std::uint8_t kProtocolIpv6Fragment = 44;
constexpr std::uint8_t kProtocolEsp = 50;
constexpr std::uint8_t kProtocolAh = 51;
constexpr std::uint8_t kProtocolIcmpv6 = 58;
constexpr std::uint8_t kProtocolIpv6NoNext = 59;
constexpr std::uint8_t kProtocolIpv6Destination = 60;

[[nodiscard]] std::uint16_t read_be16(const std::uint8_t* data) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8U) |
                                      static_cast<std::uint16_t>(data[1]));
}

[[nodiscard]] std::string hex16(std::uint16_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << value;
    return out.str();
}

[[nodiscard]] std::string format_ipv4(const std::uint8_t* data) {
    std::ostringstream out;
    out << static_cast<unsigned int>(data[0]) << '.'
        << static_cast<unsigned int>(data[1]) << '.'
        << static_cast<unsigned int>(data[2]) << '.'
        << static_cast<unsigned int>(data[3]);
    return out.str();
}

[[nodiscard]] std::string format_ipv6(const std::uint8_t* data) {
    std::array<std::uint16_t, 8> words{};
    for (std::size_t i = 0; i < words.size(); ++i) {
        words[i] = read_be16(data + (i * 2U));
    }

    // RFC 5952-style longest zero-run compression. Ties use the first run.
    std::size_t best_start = words.size();
    std::size_t best_length = 0;
    for (std::size_t i = 0; i < words.size();) {
        if (words[i] != 0) {
            ++i;
            continue;
        }
        const std::size_t start = i;
        while (i < words.size() && words[i] == 0) {
            ++i;
        }
        const std::size_t length = i - start;
        if (length >= 2 && length > best_length) {
            best_start = start;
            best_length = length;
        }
    }

    std::ostringstream out;
    out << std::hex << std::nouppercase;
    for (std::size_t i = 0; i < words.size();) {
        if (i == best_start) {
            out << "::";
            i += best_length;
            if (i == words.size()) {
                break;
            }
            continue;
        }
        if (i != 0 && i != best_start + best_length) {
            out << ':';
        }
        out << words[i];
        ++i;
    }
    return out.str();
}

[[nodiscard]] std::string protocol_name(std::uint8_t protocol) {
    switch (protocol) {
        case kProtocolIcmp:
            return "ICMP";
        case kProtocolTcp:
            return "TCP";
        case kProtocolUdp:
            return "UDP";
        case kProtocolEsp:
            return "ESP";
        case kProtocolAh:
            return "AH";
        case kProtocolIcmpv6:
            return "ICMPv6";
        case kProtocolIpv6NoNext:
            return "NO-NEXT-HEADER";
        default:
            return "IP-" + std::to_string(protocol);
    }
}

struct DnsNameResult {
    bool ok{false};
    std::string name;
    std::size_t next_offset{0};
};

[[nodiscard]] DnsNameResult parse_dns_name(
    const std::uint8_t* data,
    std::size_t length,
    std::size_t start_offset) {
    if (start_offset >= length) {
        return {};
    }

    std::string name;
    std::size_t cursor = start_offset;
    std::size_t next_offset = start_offset;
    bool jumped = false;
    std::size_t jumps = 0;
    std::unordered_set<std::size_t> visited;

    while (cursor < length) {
        const std::uint8_t label_length = data[cursor];
        if (label_length == 0) {
            if (!jumped) {
                next_offset = cursor + 1U;
            }
            return {true, name.empty() ? "." : name, next_offset};
        }

        if ((label_length & 0xC0U) == 0xC0U) {
            if (cursor + 1U >= length) {
                return {};
            }
            const std::size_t pointer =
                static_cast<std::size_t>(((label_length & 0x3FU) << 8U) | data[cursor + 1U]);
            if (pointer >= length || jumps++ >= 32U || !visited.insert(pointer).second) {
                return {};
            }
            if (!jumped) {
                next_offset = cursor + 2U;
                jumped = true;
            }
            cursor = pointer;
            continue;
        }

        if ((label_length & 0xC0U) != 0 || label_length > 63U) {
            return {};
        }
        ++cursor;
        if (cursor + label_length > length) {
            return {};
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        for (std::size_t i = 0; i < label_length; ++i) {
            const unsigned char ch = data[cursor + i];
            if (std::isalnum(ch) != 0 || ch == '-' || ch == '_' || ch == '*') {
                name.push_back(static_cast<char>(std::tolower(ch)));
            } else {
                name.push_back('?');
            }
        }
        if (name.size() > 253U) {
            return {};
        }
        cursor += label_length;
        if (!jumped) {
            next_offset = cursor;
        }
    }

    return {};
}

void parse_dns_query(
    const std::uint8_t* data,
    std::size_t length,
    PacketInfo& packet) {
    if (length < 12U) {
        return;
    }
    const std::uint16_t flags = read_be16(data + 2U);
    const std::uint16_t question_count = read_be16(data + 4U);
    const bool is_response = (flags & 0x8000U) != 0;
    if (is_response || question_count == 0U) {
        return;
    }

    const DnsNameResult name = parse_dns_name(data, length, 12U);
    if (!name.ok || name.next_offset + 4U > length) {
        return;
    }
    packet.dns_query = name.name;
    packet.dns_query_type = read_be16(data + name.next_offset);
}

void parse_transport(
    const std::uint8_t* data,
    std::size_t length,
    std::uint8_t protocol,
    bool parse_ports,
    PacketInfo& packet) {
    packet.transport_protocol = protocol_name(protocol);
    if (!parse_ports) {
        return;
    }

    if (protocol == kProtocolTcp) {
        if (length < 20U) {
            packet.status = ParseStatus::truncated;
            packet.status_detail = "truncated TCP header";
            return;
        }
        packet.source_port = read_be16(data);
        packet.destination_port = read_be16(data + 2U);
        packet.has_ports = true;
        const std::uint8_t flags = data[13U];
        packet.tcp_fin = (flags & 0x01U) != 0;
        packet.tcp_syn = (flags & 0x02U) != 0;
        packet.tcp_rst = (flags & 0x04U) != 0;
        packet.tcp_ack = (flags & 0x10U) != 0;
        return;
    }

    if (protocol == kProtocolUdp) {
        if (length < 8U) {
            packet.status = ParseStatus::truncated;
            packet.status_detail = "truncated UDP header";
            return;
        }
        packet.source_port = read_be16(data);
        packet.destination_port = read_be16(data + 2U);
        packet.has_ports = true;
        if (packet.source_port == 53U || packet.destination_port == 53U) {
            parse_dns_query(data + 8U, length - 8U, packet);
        }
    }
}

template <typename Map>
[[nodiscard]] std::vector<RankedCounter> rank_counters(const Map& values, std::size_t limit) {
    std::vector<RankedCounter> ranked;
    ranked.reserve(values.size());
    for (const auto& [key, counter] : values) {
        ranked.push_back({key, counter.packets, counter.bytes});
    }
    std::sort(ranked.begin(), ranked.end(), [](const RankedCounter& lhs, const RankedCounter& rhs) {
        if (lhs.bytes != rhs.bytes) {
            return lhs.bytes > rhs.bytes;
        }
        if (lhs.packets != rhs.packets) {
            return lhs.packets > rhs.packets;
        }
        return lhs.key < rhs.key;
    });
    if (ranked.size() > limit) {
        ranked.resize(limit);
    }
    return ranked;
}

}  // namespace

PacketInfo PacketParser::parse(
    int link_type,
    const std::uint8_t* data,
    std::size_t captured_length,
    std::size_t wire_length) {
    PacketInfo packet;
    packet.captured_length = captured_length;
    packet.wire_length = wire_length;

    if (data == nullptr || captured_length == 0U) {
        packet.status = ParseStatus::truncated;
        packet.status_detail = "empty packet";
        return packet;
    }

    std::size_t network_offset = 0;
    std::uint16_t ethertype = 0;
    bool infer_ip_version = false;

    switch (link_type) {
        case kDltEthernet: {
            if (captured_length < 14U) {
                packet.status = ParseStatus::truncated;
                packet.status_detail = "truncated Ethernet header";
                return packet;
            }
            network_offset = 14U;
            ethertype = read_be16(data + 12U);
            std::size_t vlan_depth = 0;
            while ((ethertype == kEthertypeVlan || ethertype == kEthertypeQinQ ||
                    ethertype == kEthertypeVlan9100) &&
                   vlan_depth < 4U) {
                if (captured_length < network_offset + 4U) {
                    packet.status = ParseStatus::truncated;
                    packet.status_detail = "truncated VLAN header";
                    return packet;
                }
                ethertype = read_be16(data + network_offset + 2U);
                network_offset += 4U;
                ++vlan_depth;
            }
            break;
        }
        case kDltLinuxSll:
            if (captured_length < 16U) {
                packet.status = ParseStatus::truncated;
                packet.status_detail = "truncated Linux cooked header";
                return packet;
            }
            network_offset = 16U;
            ethertype = read_be16(data + 14U);
            break;
        case kDltLinuxSll2:
            if (captured_length < 20U) {
                packet.status = ParseStatus::truncated;
                packet.status_detail = "truncated Linux cooked v2 header";
                return packet;
            }
            network_offset = 20U;
            ethertype = read_be16(data);
            break;
        case kDltRaw:
        case kLinktypeRaw:
            network_offset = 0U;
            infer_ip_version = true;
            break;
        case kDltNull:
            if (captured_length < 5U) {
                packet.status = ParseStatus::truncated;
                packet.status_detail = "truncated loopback header";
                return packet;
            }
            network_offset = 4U;
            infer_ip_version = true;
            break;
        default:
            packet.status = ParseStatus::unsupported_link;
            packet.status_detail = "unsupported datalink type " + std::to_string(link_type);
            return packet;
    }

    if (network_offset >= captured_length) {
        packet.status = ParseStatus::truncated;
        packet.status_detail = "missing network-layer header";
        return packet;
    }

    if (infer_ip_version) {
        const std::uint8_t version = static_cast<std::uint8_t>(data[network_offset] >> 4U);
        if (version == 4U) {
            ethertype = kEthertypeIpv4;
        } else if (version == 6U) {
            ethertype = kEthertypeIpv6;
        } else {
            packet.status = ParseStatus::non_ip;
            packet.network_protocol = "NON-IP";
            packet.transport_protocol = "NON-IP";
            packet.status_detail = "raw frame is not IPv4 or IPv6";
            return packet;
        }
    }

    if (ethertype == kEthertypeArp) {
        packet.status = ParseStatus::non_ip;
        packet.network_protocol = "ARP";
        packet.transport_protocol = "ARP";
        packet.status_detail = "ARP frame";
        return packet;
    }

    if (ethertype == kEthertypeIpv4) {
        packet.network_protocol = "IPv4";
        const std::size_t available = captured_length - network_offset;
        if (available < 20U) {
            packet.status = ParseStatus::truncated;
            packet.status_detail = "truncated IPv4 header";
            return packet;
        }
        const std::uint8_t version = static_cast<std::uint8_t>(data[network_offset] >> 4U);
        const std::size_t header_length =
            static_cast<std::size_t>(data[network_offset] & 0x0FU) * 4U;
        if (version != 4U || header_length < 20U) {
            packet.status = ParseStatus::malformed;
            packet.status_detail = "invalid IPv4 version or header length";
            return packet;
        }
        if (available < header_length) {
            packet.status = ParseStatus::truncated;
            packet.status_detail = "truncated IPv4 options";
            return packet;
        }
        const std::uint16_t total_length = read_be16(data + network_offset + 2U);
        if (total_length < header_length) {
            packet.status = ParseStatus::malformed;
            packet.status_detail = "IPv4 total length is smaller than header length";
            return packet;
        }
        packet.source_ip = format_ipv4(data + network_offset + 12U);
        packet.destination_ip = format_ipv4(data + network_offset + 16U);

        const std::uint16_t fragment_field = read_be16(data + network_offset + 6U);
        const std::uint16_t fragment_offset = static_cast<std::uint16_t>(fragment_field & 0x1FFFU);
        const bool more_fragments = (fragment_field & 0x2000U) != 0;
        packet.fragmented = more_fragments || fragment_offset != 0U;

        const std::uint8_t protocol = data[network_offset + 9U];
        const std::size_t bounded_ip_length = std::min<std::size_t>(available, total_length);
        const std::size_t payload_length = bounded_ip_length - header_length;
        packet.status = ParseStatus::ok;
        parse_transport(
            data + network_offset + header_length,
            payload_length,
            protocol,
            fragment_offset == 0U,
            packet);
        return packet;
    }

    if (ethertype == kEthertypeIpv6) {
        packet.network_protocol = "IPv6";
        const std::size_t available = captured_length - network_offset;
        if (available < 40U) {
            packet.status = ParseStatus::truncated;
            packet.status_detail = "truncated IPv6 header";
            return packet;
        }
        if ((data[network_offset] >> 4U) != 6U) {
            packet.status = ParseStatus::malformed;
            packet.status_detail = "invalid IPv6 version";
            return packet;
        }
        packet.source_ip = format_ipv6(data + network_offset + 8U);
        packet.destination_ip = format_ipv6(data + network_offset + 24U);

        const std::uint16_t declared_payload_length = read_be16(data + network_offset + 4U);
        const std::size_t bounded_total_length = std::min<std::size_t>(
            available,
            declared_payload_length == 0U ? available : 40U + declared_payload_length);
        std::size_t cursor = network_offset + 40U;
        const std::size_t packet_end = network_offset + bounded_total_length;
        std::uint8_t next_header = data[network_offset + 6U];
        bool parse_ports = true;

        for (std::size_t extension_count = 0; extension_count < 16U; ++extension_count) {
            if (next_header == kProtocolIpv6HopByHop ||
                next_header == kProtocolIpv6Routing ||
                next_header == kProtocolIpv6Destination) {
                if (cursor + 2U > packet_end) {
                    packet.status = ParseStatus::truncated;
                    packet.status_detail = "truncated IPv6 extension header";
                    return packet;
                }
                const std::uint8_t following = data[cursor];
                const std::size_t extension_length =
                    (static_cast<std::size_t>(data[cursor + 1U]) + 1U) * 8U;
                if (extension_length < 8U || cursor + extension_length > packet_end) {
                    packet.status = ParseStatus::truncated;
                    packet.status_detail = "truncated IPv6 extension payload";
                    return packet;
                }
                next_header = following;
                cursor += extension_length;
                continue;
            }

            if (next_header == kProtocolIpv6Fragment) {
                if (cursor + 8U > packet_end) {
                    packet.status = ParseStatus::truncated;
                    packet.status_detail = "truncated IPv6 fragment header";
                    return packet;
                }
                const std::uint8_t following = data[cursor];
                const std::uint16_t fragment_field = read_be16(data + cursor + 2U);
                const std::uint16_t fragment_offset =
                    static_cast<std::uint16_t>((fragment_field & 0xFFF8U) >> 3U);
                const bool more_fragments = (fragment_field & 0x0001U) != 0;
                packet.fragmented = more_fragments || fragment_offset != 0U;
                parse_ports = fragment_offset == 0U;
                next_header = following;
                cursor += 8U;
                continue;
            }

            if (next_header == kProtocolAh) {
                if (cursor + 2U > packet_end) {
                    packet.status = ParseStatus::truncated;
                    packet.status_detail = "truncated IPv6 AH header";
                    return packet;
                }
                const std::uint8_t following = data[cursor];
                const std::size_t extension_length =
                    (static_cast<std::size_t>(data[cursor + 1U]) + 2U) * 4U;
                if (extension_length < 8U || cursor + extension_length > packet_end) {
                    packet.status = ParseStatus::truncated;
                    packet.status_detail = "truncated IPv6 AH payload";
                    return packet;
                }
                next_header = following;
                cursor += extension_length;
                continue;
            }
            break;
        }

        if (cursor > packet_end) {
            packet.status = ParseStatus::truncated;
            packet.status_detail = "IPv6 payload offset exceeds captured data";
            return packet;
        }
        packet.status = ParseStatus::ok;
        parse_transport(data + cursor, packet_end - cursor, next_header, parse_ports, packet);
        return packet;
    }

    packet.status = ParseStatus::non_ip;
    packet.network_protocol = "ETHERTYPE-" + hex16(ethertype);
    packet.transport_protocol = packet.network_protocol;
    packet.status_detail = "non-IP Ethernet payload";
    return packet;
}

Analyzer::Analyzer() = default;

Analyzer::Analyzer(Config config) : config_(config) {}

void Analyzer::consume(const PacketInfo& packet, double timestamp_seconds) {
    ++summary_.total_packets;
    summary_.total_captured_bytes += packet.captured_length;
    summary_.total_wire_bytes += packet.wire_length;
    if (packet.captured_length < packet.wire_length || packet.status == ParseStatus::truncated) {
        ++summary_.truncated_packets;
    }
    if (packet.fragmented) {
        ++summary_.fragmented_packets;
    }

    switch (packet.status) {
        case ParseStatus::ok:
            ++summary_.parsed_packets;
            break;
        case ParseStatus::non_ip:
            ++summary_.non_ip_packets;
            break;
        case ParseStatus::unsupported_link:
            ++summary_.unsupported_link_packets;
            break;
        case ParseStatus::malformed:
            ++summary_.malformed_packets;
            break;
        case ParseStatus::truncated:
            break;
    }

    const std::string protocol = packet.transport_protocol.empty()
        ? parse_status_name(packet.status)
        : packet.transport_protocol;
    Counter& protocol_counter = protocols_[protocol];
    ++protocol_counter.packets;
    protocol_counter.bytes += packet.wire_length;

    if (!packet.source_ip.empty()) {
        Counter& counter = sources_[packet.source_ip];
        ++counter.packets;
        counter.bytes += packet.wire_length;
    }
    if (!packet.destination_ip.empty()) {
        Counter& counter = destinations_[packet.destination_ip];
        ++counter.packets;
        counter.bytes += packet.wire_length;
    }
    if (packet.has_ports) {
        const std::string key = std::to_string(packet.destination_port) + "/" + protocol;
        Counter& counter = destination_ports_[key];
        ++counter.packets;
        counter.bytes += packet.wire_length;
    }

    if (packet.dns_query.has_value()) {
        ++summary_.dns_queries;
        ++dns_queries_[*packet.dns_query];
        if (!packet.source_ip.empty()) {
            ++dns_queries_by_source_[packet.source_ip];
        }
    }

    if (packet.tcp_syn && !packet.tcp_ack && packet.has_ports && !packet.source_ip.empty()) {
        syn_targets_by_source_[packet.source_ip].insert(
            packet.destination_ip + ":" + std::to_string(packet.destination_port));
    }

    if (packet.status != ParseStatus::ok || packet.source_ip.empty() ||
        packet.destination_ip.empty()) {
        return;
    }

    FlowKey key{
        packet.source_ip,
        packet.destination_ip,
        protocol,
        packet.has_ports ? packet.source_port : static_cast<std::uint16_t>(0),
        packet.has_ports ? packet.destination_port : static_cast<std::uint16_t>(0),
    };
    auto flow = flows_.find(key);
    if (flow == flows_.end()) {
        if (flows_.size() >= config_.max_flows) {
            ++summary_.dropped_new_flows;
            return;
        }
        FlowStats initial;
        initial.first_timestamp = timestamp_seconds;
        initial.last_timestamp = timestamp_seconds;
        flow = flows_.emplace(std::move(key), initial).first;
    }
    FlowStats& stats = flow->second;
    ++stats.packets;
    stats.bytes += packet.wire_length;
    stats.tcp_syn_packets += packet.tcp_syn ? 1U : 0U;
    stats.tcp_rst_packets += packet.tcp_rst ? 1U : 0U;
    stats.last_timestamp = timestamp_seconds;
}

const Summary& Analyzer::summary() const noexcept {
    return summary_;
}

std::vector<RankedCounter> Analyzer::protocol_counters() const {
    return rank_counters(protocols_, protocols_.size());
}

std::vector<RankedCounter> Analyzer::top_sources(std::size_t limit) const {
    return rank_counters(sources_, limit);
}

std::vector<RankedCounter> Analyzer::top_destinations(std::size_t limit) const {
    return rank_counters(destinations_, limit);
}

std::vector<RankedCounter> Analyzer::top_destination_ports(std::size_t limit) const {
    return rank_counters(destination_ports_, limit);
}

std::vector<RankedValue> Analyzer::top_dns_queries(std::size_t limit) const {
    std::vector<RankedValue> ranked;
    ranked.reserve(dns_queries_.size());
    for (const auto& [name, count] : dns_queries_) {
        ranked.push_back({name, count});
    }
    std::sort(ranked.begin(), ranked.end(), [](const RankedValue& lhs, const RankedValue& rhs) {
        if (lhs.count != rhs.count) {
            return lhs.count > rhs.count;
        }
        return lhs.key < rhs.key;
    });
    if (ranked.size() > limit) {
        ranked.resize(limit);
    }
    return ranked;
}

std::vector<FlowRecord> Analyzer::top_flows(std::size_t limit) const {
    std::vector<FlowRecord> ranked;
    ranked.reserve(flows_.size());
    for (const auto& [key, stats] : flows_) {
        ranked.push_back({
            key.source_ip,
            key.destination_ip,
            key.protocol,
            key.source_port,
            key.destination_port,
            stats.packets,
            stats.bytes,
            stats.tcp_syn_packets,
            stats.tcp_rst_packets,
            stats.first_timestamp,
            stats.last_timestamp,
        });
    }
    std::sort(ranked.begin(), ranked.end(), [](const FlowRecord& lhs, const FlowRecord& rhs) {
        if (lhs.bytes != rhs.bytes) {
            return lhs.bytes > rhs.bytes;
        }
        if (lhs.packets != rhs.packets) {
            return lhs.packets > rhs.packets;
        }
        return std::tie(lhs.source_ip, lhs.destination_ip, lhs.source_port, lhs.destination_port) <
               std::tie(rhs.source_ip, rhs.destination_ip, rhs.source_port, rhs.destination_port);
    });
    if (ranked.size() > limit) {
        ranked.resize(limit);
    }
    return ranked;
}

std::vector<Alert> Analyzer::alerts() const {
    std::vector<Alert> result;
    if (config_.syn_scan_threshold > 0U) {
        for (const auto& [source, targets] : syn_targets_by_source_) {
            if (targets.size() < config_.syn_scan_threshold) {
                continue;
            }
            const bool high = targets.size() >=
                static_cast<std::size_t>(config_.syn_scan_threshold) * 5U;
            result.push_back({
                high ? "high" : "medium",
                "tcp_syn_scan",
                source,
                "Source sent SYN packets without ACK to " + std::to_string(targets.size()) +
                    " unique destination/port targets",
                targets.size(),
            });
        }
    }

    if (config_.dns_query_threshold > 0U) {
        for (const auto& [source, count] : dns_queries_by_source_) {
            if (count < config_.dns_query_threshold) {
                continue;
            }
            result.push_back({
                count >= static_cast<std::uint64_t>(config_.dns_query_threshold) * 5U
                    ? "high"
                    : "medium",
                "dns_query_volume",
                source,
                "Source generated " + std::to_string(count) +
                    " DNS queries in the analyzed capture",
                count,
            });
        }
    }

    if (summary_.dropped_new_flows > 0U) {
        result.push_back({
            "low",
            "flow_table_saturated",
            "analyzer",
            "Flow cardinality exceeded --max-flows; some new flow keys were not retained",
            summary_.dropped_new_flows,
        });
    }

    std::sort(result.begin(), result.end(), [](const Alert& lhs, const Alert& rhs) {
        const auto severity_rank = [](const std::string& value) {
            if (value == "high") {
                return 3;
            }
            if (value == "medium") {
                return 2;
            }
            return 1;
        };
        const int left = severity_rank(lhs.severity);
        const int right = severity_rank(rhs.severity);
        if (left != right) {
            return left > right;
        }
        if (lhs.evidence_count != rhs.evidence_count) {
            return lhs.evidence_count > rhs.evidence_count;
        }
        return lhs.source < rhs.source;
    });
    return result;
}

bool Analyzer::FlowKey::operator==(const FlowKey& other) const noexcept {
    return source_port == other.source_port &&
           destination_port == other.destination_port &&
           source_ip == other.source_ip &&
           destination_ip == other.destination_ip &&
           protocol == other.protocol;
}

std::size_t Analyzer::FlowKeyHash::operator()(const FlowKey& key) const noexcept {
    const auto combine = [](std::size_t seed, std::size_t value) {
        return seed ^ (value + 0x9E3779B97F4A7C15ULL + (seed << 6U) + (seed >> 2U));
    };
    std::size_t seed = std::hash<std::string>{}(key.source_ip);
    seed = combine(seed, std::hash<std::string>{}(key.destination_ip));
    seed = combine(seed, std::hash<std::string>{}(key.protocol));
    seed = combine(seed, std::hash<std::uint16_t>{}(key.source_port));
    seed = combine(seed, std::hash<std::uint16_t>{}(key.destination_port));
    return seed;
}

std::string parse_status_name(ParseStatus status) {
    switch (status) {
        case ParseStatus::ok:
            return "ok";
        case ParseStatus::non_ip:
            return "non_ip";
        case ParseStatus::unsupported_link:
            return "unsupported_link";
        case ParseStatus::truncated:
            return "truncated";
        case ParseStatus::malformed:
            return "malformed";
    }
    return "unknown";
}

std::string json_escape(std::string_view value) {
    std::ostringstream out;
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"':
                out << "\\\"";
                break;
            case '\\':
                out << "\\\\";
                break;
            case '\b':
                out << "\\b";
                break;
            case '\f':
                out << "\\f";
                break;
            case '\n':
                out << "\\n";
                break;
            case '\r':
                out << "\\r";
                break;
            case '\t':
                out << "\\t";
                break;
            default:
                if (ch < 0x20U) {
                    out << "\\u" << std::hex << std::uppercase << std::setw(4)
                        << std::setfill('0') << static_cast<unsigned int>(ch)
                        << std::dec << std::nouppercase;
                } else {
                    out << static_cast<char>(ch);
                }
        }
    }
    return out.str();
}

}  // namespace cherry::pcap
