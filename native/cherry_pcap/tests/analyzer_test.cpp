#include "cherry_pcap/analyzer.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

using cherry::pcap::Analyzer;
using cherry::pcap::PacketInfo;
using cherry::pcap::PacketParser;
using cherry::pcap::ParseStatus;

void require(bool condition, const std::string& message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

void push_be16(std::vector<std::uint8_t>& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
}

std::vector<std::uint8_t> ethernet_header(std::uint16_t ethertype) {
    std::vector<std::uint8_t> packet(12U, 0U);
    push_be16(packet, ethertype);
    return packet;
}

void append_ipv4_header(
    std::vector<std::uint8_t>& packet,
    std::uint16_t total_length,
    std::uint8_t protocol,
    const std::vector<std::uint8_t>& source,
    const std::vector<std::uint8_t>& destination) {
    packet.push_back(0x45U);
    packet.push_back(0U);
    push_be16(packet, total_length);
    push_be16(packet, 1U);
    push_be16(packet, 0x4000U);
    packet.push_back(64U);
    packet.push_back(protocol);
    push_be16(packet, 0U);
    packet.insert(packet.end(), source.begin(), source.end());
    packet.insert(packet.end(), destination.begin(), destination.end());
}

std::vector<std::uint8_t> make_tcp_syn_packet(
    std::uint16_t source_port,
    std::uint16_t destination_port,
    std::uint8_t destination_host = 2U) {
    std::vector<std::uint8_t> packet = ethernet_header(0x0800U);
    append_ipv4_header(packet, 40U, 6U, {10U, 0U, 0U, 1U}, {10U, 0U, 0U, destination_host});
    push_be16(packet, source_port);
    push_be16(packet, destination_port);
    packet.insert(packet.end(), 8U, 0U);
    packet.push_back(0x50U);
    packet.push_back(0x02U);
    packet.insert(packet.end(), 6U, 0U);
    return packet;
}

std::vector<std::uint8_t> make_vlan_dns_query() {
    std::vector<std::uint8_t> dns;
    push_be16(dns, 0x1234U);
    push_be16(dns, 0x0100U);
    push_be16(dns, 1U);
    push_be16(dns, 0U);
    push_be16(dns, 0U);
    push_be16(dns, 0U);
    dns.push_back(7U);
    for (const char ch : std::string("Example")) {
        dns.push_back(static_cast<std::uint8_t>(ch));
    }
    dns.push_back(3U);
    for (const char ch : std::string("COM")) {
        dns.push_back(static_cast<std::uint8_t>(ch));
    }
    dns.push_back(0U);
    push_be16(dns, 1U);
    push_be16(dns, 1U);

    std::vector<std::uint8_t> packet(12U, 0U);
    push_be16(packet, 0x8100U);
    push_be16(packet, 1U);
    push_be16(packet, 0x0800U);
    const std::uint16_t ip_length = static_cast<std::uint16_t>(20U + 8U + dns.size());
    append_ipv4_header(packet, ip_length, 17U, {192U, 168U, 1U, 10U}, {8U, 8U, 8U, 8U});
    push_be16(packet, 53000U);
    push_be16(packet, 53U);
    push_be16(packet, static_cast<std::uint16_t>(8U + dns.size()));
    push_be16(packet, 0U);
    packet.insert(packet.end(), dns.begin(), dns.end());
    return packet;
}

void test_tcp_syn_parser() {
    const auto bytes = make_tcp_syn_packet(12345U, 443U);
    const PacketInfo packet = PacketParser::parse(
        cherry::pcap::kDltEthernet, bytes.data(), bytes.size(), bytes.size());
    require(packet.status == ParseStatus::ok, "TCP SYN should parse");
    require(packet.network_protocol == "IPv4", "TCP SYN should be IPv4");
    require(packet.transport_protocol == "TCP", "TCP SYN should be TCP");
    require(packet.source_ip == "10.0.0.1", "source IPv4 should match");
    require(packet.destination_ip == "10.0.0.2", "destination IPv4 should match");
    require(packet.source_port == 12345U && packet.destination_port == 443U, "TCP ports should match");
    require(packet.tcp_syn && !packet.tcp_ack, "SYN flag should be recognized");
}

void test_vlan_dns_parser() {
    const auto bytes = make_vlan_dns_query();
    const PacketInfo packet = PacketParser::parse(
        cherry::pcap::kDltEthernet, bytes.data(), bytes.size(), bytes.size());
    require(packet.status == ParseStatus::ok, "VLAN DNS packet should parse");
    require(packet.transport_protocol == "UDP", "DNS query should be UDP");
    require(packet.destination_port == 53U, "DNS destination port should be 53");
    require(packet.dns_query.has_value(), "DNS query name should be extracted");
    require(*packet.dns_query == "example.com", "DNS query should be normalized to lowercase");
    require(packet.dns_query_type.has_value() && *packet.dns_query_type == 1U, "DNS QTYPE should be A");
}

void test_truncated_frame() {
    const std::vector<std::uint8_t> bytes(8U, 0U);
    const PacketInfo packet = PacketParser::parse(
        cherry::pcap::kDltEthernet, bytes.data(), bytes.size(), 64U);
    require(packet.status == ParseStatus::truncated, "short Ethernet frame should be truncated");
}

void test_scan_alert() {
    Analyzer analyzer({100U, 3U, 100U});
    for (const std::uint16_t port : std::array<std::uint16_t, 3>{22U, 80U, 443U}) {
        const auto bytes = make_tcp_syn_packet(45000U, port);
        const PacketInfo packet = PacketParser::parse(
            cherry::pcap::kDltEthernet, bytes.data(), bytes.size(), bytes.size());
        analyzer.consume(packet, static_cast<double>(port));
    }
    const auto alerts = analyzer.alerts();
    require(alerts.size() == 1U, "three unique SYN targets should trigger one scan alert");
    require(alerts.front().type == "tcp_syn_scan", "alert type should be tcp_syn_scan");
    require(alerts.front().source == "10.0.0.1", "alert source should match scanner");
    require(alerts.front().evidence_count == 3U, "alert evidence count should match unique targets");
}

void test_json_escape() {
    require(
        cherry::pcap::json_escape("a\n\"b\\c") == "a\\n\\\"b\\\\c",
        "JSON escaping should cover control characters, quote, and slash");
}

}  // namespace

int main() {
    test_tcp_syn_parser();
    test_vlan_dns_parser();
    test_truncated_frame();
    test_scan_alert();
    test_json_escape();
    std::cout << "cherry_pcap_core tests passed\n";
    return 0;
}
