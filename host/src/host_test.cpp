// src/host_test.cpp
#include "packet_format_test.hpp"
#include "socket_utils.hpp"

#ifndef __linux__
#error "host_test.cpp can only be built/run on Linux (AF_PACKET). Use host_udp on macOS for testing."
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
constexpr int NUM_PACKETS   = 5;   // number of distinct flows (pktid)
constexpr int MAX_ITER      = 15;  // safety stop based on hopid (TTL)
constexpr int NUM_MASK_ITERS = 6;  // how many mask values we use per flow

constexpr uint16_t SWITCH_MASK_SEQ[NUM_MASK_ITERS] = {
    1,   // 0000 0000 0000 0001
    3,   // 0000 0000 0000 0011
    7,   // 0000 0000 0000 0111
    10,  // 0000 0000 0000 1010
    11,  // 0000 0000 0000 1011
    13   // 0000 0000 0000 1101
};

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
    uint32_t src_ip = inet_addr("10.0.0.1");
    uint32_t dst_ip = inet_addr("10.0.0.2");

    std::vector<bool> done(NUM_PACKETS + 1, false);
    std::vector<int> iter_cnt(NUM_PACKETS + 1, 0);

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
        // Initial mask for first iteration of this flow.
        // We treat this as iteration 0, so use SWITCH_MASK_SEQ[0].
        recipe.switch_mask = htons(SWITCH_MASK_SEQ[0]);
        recipe.pint        = htons(0);
        recipe.xor_degree  = 0;

        iter_cnt[pktid] = 1;

        std::vector<uint8_t> frame(
            sizeof(ethernet_h) + sizeof(ipv4_h) + sizeof(recipe_h));
        std::memcpy(frame.data(), &eth, sizeof(eth));
        std::memcpy(frame.data() + sizeof(eth), &ip, sizeof(ip));
        std::memcpy(frame.data() + sizeof(eth) + sizeof(ip),
                    &recipe, sizeof(recipe));

        std::string fname = "output/packet_" + std::to_string(pktid) + ".csv";
        std::ofstream packet_log(fname);
        if (!packet_log) {
            std::cerr << "[host] Failed to open " << fname
                      << " for writing\n";
            close(sockfd);
            return 1;
        }
        packet_log << "hopid,ttl,switch_mask,pint,xor_degree\n";

        // Log initial packet (hopid=0, ttl=255)
        uint8_t  init_ttl   = ip.ttl;
        int      init_hopid = 255 - init_ttl;
        uint16_t init_mask  = ntohs(recipe.switch_mask);
        uint16_t init_pint  = ntohs(recipe.pint);
        uint8_t  init_xdeg  = recipe.xor_degree;

        std::cout << "[host] init pktid=" << pktid
                  << " hopid=" << init_hopid
                  << " ttl=" << static_cast<int>(init_ttl)
                  << " mask=" << init_mask
                  << " pint=" << init_pint
                  << " xor=" << static_cast<int>(init_xdeg) << "\n";

        packet_log << init_hopid << "," << static_cast<int>(init_ttl)
                   << "," << init_mask << ","
                   << init_pint << ","
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
            continue;
        }

        auto* rx_eth = reinterpret_cast<ethernet_h*>(rx.data());
        if (ntohs(rx_eth->ether_type) != 0x0800) {
            continue;
        }

        auto* rx_ip = reinterpret_cast<ipv4_h*>(
            rx.data() + sizeof(ethernet_h));
        if (rx_ip->protocol != 146) {
            continue;
        }

        auto* rx_rec = reinterpret_cast<recipe_h*>(
            rx.data() + sizeof(ethernet_h) + sizeof(ipv4_h));

        uint16_t rx_pktid = ntohs(rx_ip->identification);
        if (rx_pktid == 0 || rx_pktid > NUM_PACKETS) {
            continue;
        }

        uint8_t  ttl       = rx_ip->ttl;
        int      hopid     = 255 - ttl;
        uint16_t switch_ms = ntohs(rx_rec->switch_mask);
        uint16_t pint      = ntohs(rx_rec->pint);
        uint8_t  xor_deg   = rx_rec->xor_degree;

        std::cout << "[host] recv pktid=" << rx_pktid
                  << " hopid=" << hopid
                  << " ttl=" << static_cast<int>(ttl)
                  << " mask=" << switch_ms
                  << " pint=" << pint
                  << " xor=" << static_cast<int>(xor_deg) << "\n";

        // Append to that packet's CSV
        std::string fname = "output/packet_" + std::to_string(rx_pktid) + ".csv";
        std::ofstream packet_log(fname, std::ios::app);
        if (!packet_log) {
            std::cerr << "[host] Failed to append to " << fname << "\n";
        } else {
            packet_log << hopid << "," << static_cast<int>(ttl)
                       << "," << switch_ms << ","
                       << pint << ","
                       << static_cast<int>(xor_deg) << "\n";
            packet_log.close();
        }

        if (ttl == 0 || hopid >= MAX_ITER ||
            iter_cnt[rx_pktid] >= NUM_MASK_ITERS) {
            done[rx_pktid] = true;
            std::cout << "[host] Marking pktid=" << rx_pktid
                      << " as done (ttl=" << static_cast<int>(ttl)
                      << ", hopid=" << hopid
                      << ", iter_cnt=" << iter_cnt[rx_pktid] << ")\n";
            continue;
        }

        // --------------------------
        // Update switch_mask for NEXT iteration of this flow
        // --------------------------
        int next_iter = iter_cnt[rx_pktid];
        uint16_t next_mask = SWITCH_MASK_SEQ[next_iter];
        rx_rec->switch_mask = htons(next_mask);
        iter_cnt[rx_pktid]++;

        // Re-arm Ethernet src/dst
        std::memcpy(rx_eth->dst, tofino_mac, 6);
        std::memcpy(rx_eth->src, host_mac, 6);

        // Send back to Tofino
        if (!send_frame(sockfd, rx, ifindex, tofino_mac)) {
            std::cerr << "[host] Failed to echo pktid=" << rx_pktid << "\n";
        }
    }

    std::cout << "[host] All packets done, exiting.\n";

    close(sockfd);
    return 0;
}