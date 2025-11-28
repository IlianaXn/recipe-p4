// src/host_loop.cpp
#include "packet_format.hpp"
#include "socket_utils.hpp"

#ifndef __linux__
#error "host_loop.cpp can only be built/run on Linux (AF_PACKET). Use host_udp on macOS for testing."
#endif

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// Experiment parameters
constexpr int NUM_PACKETS = 2500;
constexpr int MAX_ITER    = 64;

static void ensure_output_directory() {
    struct stat st{};
    if (stat("output", &st) == -1) {
        if (mkdir("output", 0755) == 0) {
            std::cout << "[host] Created output/ directory\n";
        } else {
            perror("[host] mkdir output");
        }
    }
}

// Helper: check if all packets are done
static bool all_done(const std::vector<bool>& done) {
    for (int i = 1; i <= NUM_PACKETS; ++i) {
        if (!done[i]) return false;
    }
    return true;
}

int main() {
    ensure_output_directory();

    // CHANGE this to the NIC connected to your Tofino
    std::string ifname = "veth1";

    uint8_t host_mac[6]   = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t tofino_mac[6] = {0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};

    int ifindex = 0;
    int sockfd  = open_raw_socket(ifname, ifindex);
    if (sockfd < 0) {
        std::cerr << "Failed to open raw socket on " << ifname << "\n";
        return 1;
    }

    std::cout << "[host] Using interface " << ifname
              << " (ifindex=" << ifindex << ")\n";

    // Flow for all packets
    uint32_t src_ip = inet_addr("100.0.0.1");
    uint32_t dst_ip = inet_addr("200.0.0.1");

    std::vector<bool> done(NUM_PACKETS + 1, false);

    // --------------------------
    // 1) Send initial packets for pktid=1..NUM_PACKETS
    // --------------------------
    for (int p = 1; p <= NUM_PACKETS; ++p) {
        uint16_t pktid = static_cast<uint16_t>(p);

        ethernet_h eth{};
        std::memcpy(eth.src, host_mac, 6);
        std::memcpy(eth.dst, tofino_mac, 6);
        eth.ether_type = htons(0x0800);

        ipv4_h ip{};
        ip.version_ihl       = (4 << 4) | 5;
        ip.tos               = 0;

        uint16_t ip_total_len = static_cast<uint16_t>(
            sizeof(ipv4_h) + sizeof(recipe_h));
        ip.total_len          = htons(ip_total_len);

        ip.identification    = htons(pktid);
        ip.flags_frag_offset = htons(0x4000);
        ip.ttl               = 255;
        ip.protocol          = 146;
        ip.hdr_checksum      = 0;
        ip.src_addr          = src_ip;
        ip.dst_addr          = dst_ip;
        ip.hdr_checksum      = ip_checksum(&ip, sizeof(ipv4_h));

        recipe_h recipe{};
        recipe.pint       = htons(0);
        recipe.xor_degree = 0;

        std::vector<uint8_t> frame(
            sizeof(ethernet_h) + sizeof(ipv4_h) + sizeof(recipe_h));
        std::memcpy(frame.data(), &eth, sizeof(eth));
        std::memcpy(frame.data() + sizeof(eth), &ip, sizeof(ip));
        std::memcpy(frame.data() + sizeof(eth) + sizeof(ip),
                    &recipe, sizeof(recipe));

        // Per-packet CSV in output/
        std::string fname = "output/packet_" + std::to_string(pktid) + ".csv";
        std::ofstream packet_log(fname);
        if (!packet_log) {
            std::cerr << "[host] Failed to open " << fname
                      << " for writing\n";
            close(sockfd);
            return 1;
        }
        packet_log << "hopid,ttl,pint,xor_degree\n";

        // Log initial packet (hopid=0, ttl=255)
        uint8_t  init_ttl   = ip.ttl;
        int      init_hopid = 255 - init_ttl;  // 0
        uint16_t init_pint  = ntohs(recipe.pint);
        uint8_t  init_xdeg  = recipe.xor_degree;

        std::cout << "[host] init pktid=" << pktid
                  << " hopid=" << init_hopid
                  << " ttl=" << static_cast<int>(init_ttl)
                  << " pint=" << init_pint
                  << " xor=" << static_cast<int>(init_xdeg) << "\n";

        packet_log << init_hopid << "," << static_cast<int>(init_ttl)
                   << "," << init_pint << ","
                   << static_cast<int>(init_xdeg) << "\n";
        packet_log.close();

        // Send initial frame
        if (!send_frame(sockfd, frame, ifindex, tofino_mac)) {
            std::cerr << "[host] Failed to send initial frame for pktid="
                      << pktid << "\n";
            done[pktid] = true;
            continue;
        }
    }

    // --------------------------
    // 2) Global receive/respond loop
    // --------------------------
    std::cout << "[host] Entering global receive/respond loop...\n";

    while (!all_done(done)) {
        std::vector<uint8_t> rx;
        if (!recv_frame(sockfd, rx)) {
            std::cerr << "[host] recv_frame failed, continuing...\n";
            continue;
        }

        if (rx.size() <
            sizeof(ethernet_h) + sizeof(ipv4_h) + sizeof(recipe_h)) {
            std::cout << "[host] Received frame too short, continuing...\n";
            continue;
        }

        auto* rx_eth = reinterpret_cast<ethernet_h*>(rx.data());
        if (ntohs(rx_eth->ether_type) != 0x0800) {
            std::cout << "[host] Received non-IPv4 frame, continuing...\n";
            continue;
        }

        auto* rx_ip = reinterpret_cast<ipv4_h*>(
            rx.data() + sizeof(ethernet_h));
        if (rx_ip->protocol != 146) {
            std::cout << "[host] Received non-protocol-146 IPv4 frame, continuing...\n";
            continue;
        }

        auto* rx_rec = reinterpret_cast<recipe_h*>(
            rx.data() + sizeof(ethernet_h) + sizeof(ipv4_h));

        uint16_t rx_pktid = ntohs(rx_ip->identification);
        if (rx_pktid == 0 || rx_pktid > NUM_PACKETS) {
            std::cout << "[host] Received pktid=" << rx_pktid << " out of range, continuing...\n";
            continue;
        }

        uint8_t  ttl     = rx_ip->ttl;
        int      hopid   = 255 - ttl;
        uint16_t pint    = ntohs(rx_rec->pint);
        uint8_t  xor_deg = rx_rec->xor_degree;

        std::cout << "[host] recv pktid=" << rx_pktid
                  << " hopid=" << hopid
                  << " ttl=" << static_cast<int>(ttl)
                  << " pint=" << pint
                  << " xor=" << static_cast<int>(xor_deg) << "\n";

        // Append to that packet's CSV
        std::string fname = "output/packet_" + std::to_string(rx_pktid) + ".csv";
        std::ofstream packet_log(fname, std::ios::app);
        if (!packet_log) {
            std::cerr << "[host] Failed to append to " << fname << "\n";
        } else {
            packet_log << hopid << "," << static_cast<int>(ttl)
                       << "," << pint << ","
                       << static_cast<int>(xor_deg) << "\n";
            packet_log.close();
        }

        // Stop echoing this pktid once TTL is 0 or hopid >= MAX_ITER
        if (ttl == 0 || hopid >= MAX_ITER) {
            done[rx_pktid] = true;
            std::cout << "[host] Marking pktid=" << rx_pktid
                      << " as done\n";
            continue;
        }

        std::memcpy(rx_eth->dst, tofino_mac, 6);
        std::memcpy(rx_eth->src, host_mac, 6);

        if (!send_frame(sockfd, rx, ifindex, tofino_mac)) {
            std::cerr << "[host] Failed to echo pktid=" << rx_pktid
                      << "\n";
        }
    }

    std::cout << "[host] All packets done, exiting.\n";

    close(sockfd);
    return 0;
}