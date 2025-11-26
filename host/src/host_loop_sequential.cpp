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

constexpr int NUM_PACKETS = 200;
constexpr int MAX_ITER    = 15;

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

int main() {
    ensure_output_directory();

    // CHANGE this to the NIC connected to your Tofino
    std::string ifname = "ens1f0";
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

    // Use a single flow (src/dst IP) for all packets - test
    uint32_t src_ip = inet_addr("10.0.0.1");
    uint32_t dst_ip = inet_addr("10.0.0.2");

    for (int p = 1; p <= NUM_PACKETS; ++p) {
        uint16_t pktid = static_cast<uint16_t>(p);

        // --------------------------
        // Build initial frame for this packet
        // --------------------------
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

        // Build first frame buffer (Ethernet + IPv4 + RECIPE)
        std::vector<uint8_t> frame(
            sizeof(ethernet_h) + sizeof(ipv4_h) + sizeof(recipe_h));
        std::memcpy(frame.data(), &eth, sizeof(eth));
        std::memcpy(frame.data() + sizeof(eth), &ip, sizeof(ip));
        std::memcpy(frame.data() + sizeof(eth) + sizeof(ip), &recipe,
                    sizeof(recipe));

        std::cout << "[host] === Starting packet pktid=" << pktid
                  << " ttl=255 ===\n";

        // --------------------------
        // Per-packet CSV in output/
        // --------------------------
        std::string fname = "output/packet_" + std::to_string(pktid) + ".csv";
        std::ofstream packet_log(fname);
        if (!packet_log) {
            std::cerr << "[host] Failed to open " << fname << " for writing\n";
            close(sockfd);
            return 1;
        }
        packet_log << "hopid,ttl,pint,xor_degree\n";

        // ---- Log initial packet (before sending) ----
        {
            uint8_t  init_ttl   = ip.ttl;
            int      init_hopid = 255 - init_ttl;
            uint16_t init_pint  = ntohs(recipe.pint);
            uint8_t  init_xdeg  = recipe.xor_degree;

            std::cout << "[host] pktid=" << pktid
                      << " init hopid=" << init_hopid
                      << " ttl=" << static_cast<int>(init_ttl)
                      << " pint=" << init_pint
                      << " xor=" << static_cast<int>(init_xdeg)
                      << "\n";

            packet_log << init_hopid << ","
                       << static_cast<int>(init_ttl) << ","
                       << init_pint << ","
                       << static_cast<int>(init_xdeg) << "\n";
        }

        // ---- Send initial frame ----
        if (!send_frame(sockfd, frame, ifindex, tofino_mac)) {
            std::cerr << "[host] Failed to send initial frame for pktid="
                      << pktid << "\n";
            packet_log.close();
            continue;
        }

        // --------------------------
        // MIRROR LOOP: recv → log → resend
        // --------------------------
        for (int iter = 1; iter <= MAX_ITER; ++iter) {
            std::vector<uint8_t> rx;
            if (!recv_frame(sockfd, rx)) {
                std::cerr << "[host] Failed to receive at iter " << iter
                          << " for pktid=" << pktid << "\n";
                break;
            }

            if (rx.size() <
                sizeof(ethernet_h) + sizeof(ipv4_h) + sizeof(recipe_h)) {
                std::cerr << "[host] Frame too short, skipping\n";
                continue;
            }

            auto* rx_eth = reinterpret_cast<ethernet_h*>(rx.data());
            auto* rx_ip  =
                reinterpret_cast<ipv4_h*>(rx.data() + sizeof(ethernet_h));
            auto* rx_rec = reinterpret_cast<recipe_h*>(
                rx.data() + sizeof(ethernet_h) + sizeof(ipv4_h));

            if (ntohs(rx_eth->ether_type) != 0x0800) {
                continue;
            }

            uint16_t rx_pktid = ntohs(rx_ip->identification);
            uint8_t  ttl      = rx_ip->ttl;
            int      hopid    = 255 - ttl;
            uint16_t pint     = ntohs(rx_rec->pint);
            uint8_t  xor_deg  = rx_rec->xor_degree;

            // Sanity: ensure pktid stayed the same
            if (rx_pktid != pktid) {
                std::cerr << "[host] WARNING: received pktid=" << rx_pktid
                          << " but expecting pktid=" << pktid
                          << " (skipping this frame)\n";
                continue;
            }

            std::cout << "[host] pktid=" << pktid
                      << " iter=" << iter
                      << " ttl=" << static_cast<int>(ttl)
                      << " hopid=" << hopid
                      << " pint=" << pint
                      << " xor=" << static_cast<int>(xor_deg)
                      << "\n";

            // Log this received packet (one hop row)
            packet_log << hopid << "," << static_cast<int>(ttl) << ","
                       << pint << "," << static_cast<int>(xor_deg) << "\n";

            // Stop condition
            if (ttl == 0 || hopid >= MAX_ITER) {
                std::cout << "[host] Stopping pktid=" << pktid
                          << " after iter=" << iter << "\n";
                break;
            }

            // Prepare for next iteration:
            // keep IPv4 + RECIPE exactly as Tofino produced them,
            // just fix Ethernet src/dst MACs before sending back.
            std::memcpy(rx_eth->dst, tofino_mac, 6);
            std::memcpy(rx_eth->src, host_mac, 6);

            if (!send_frame(sockfd, rx, ifindex, tofino_mac)) {
                std::cerr << "[host] Failed to echo frame at iter=" << iter
                          << " for pktid=" << pktid << "\n";
                break;
            }
        }

        packet_log.close();
    }

    close(sockfd);
    return 0;
}