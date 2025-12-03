// src/host_loop.cpp
#include "packet_format.hpp"
#include "socket_utils.hpp"

#ifndef __linux__
#error "host_loop.cpp can only be built/run on Linux (AF_PACKET). Use host_udp on macOS for testing."
#endif

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
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
constexpr int NUM_PACKETS = 500;
constexpr int MAX_ITER    = 1;

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
    std::string ifname = "enp7s0np0";

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

    // Increase socket buffer sizes aggressively to handle burst traffic
    long int rcvbuf = (long int) 128 * 1024 * 1024;  // 128 MB
    long int sndbuf = (long int) 128 * 1024 * 1024;  // 128 MB
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("setsockopt SO_RCVBUF");
    } else {
        std::cout << "[host] Set SO_RCVBUF to " << rcvbuf << " bytes\n";
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) < 0) {
        perror("setsockopt SO_SNDBUF");
    } else {
        std::cout << "[host] Set SO_SNDBUF to " << sndbuf << " bytes\n";
    }

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

        // Commented out file I/O to reduce packet drops
        // // Per-packet CSV in output/
        // std::string fname = "output/packet_" + std::to_string(pktid) + ".csv";
        // std::ofstream packet_log(fname);
        // if (!packet_log) {
        //     std::cerr << "[host] Failed to open " << fname
        //               << " for writing\n";
        //     close(sockfd);
        //     return 1;
        // }
        // packet_log << "hopid,ttl,pint,xor_degree\n";

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

        // packet_log << init_hopid << "," << static_cast<int>(init_ttl)
        //            << "," << init_pint << ","
        //            << static_cast<int>(init_xdeg) << "\n";
        // packet_log.close();

        // Send initial frame
        if (!send_frame(sockfd, frame, ifindex, tofino_mac)) {
            std::cerr << "[host] Failed to send initial frame for pktid="
                      << pktid << "\n";
            done[pktid] = true;
            continue;
        }

        // Add delay between sends to avoid overwhelming the switch
        usleep(10000);  // 10ms delay between packets
    }

    // --------------------------
    // 2) Global receive/respond loop
    // --------------------------
    

    close(sockfd);
    return 0;
}
