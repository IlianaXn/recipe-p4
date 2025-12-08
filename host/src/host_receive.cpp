// src/host_receive.cpp
#include "packet_format.hpp"
#include "socket_utils.hpp"

#ifndef __linux__
#error "host_receive.cpp can only be built/run on Linux (AF_PACKET)."
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
    // Change this to the NIC connected to Tofino
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

    std::vector<bool> done(NUM_PACKETS + 1, false);

    // global log file for all packets
    std::ofstream global_log("output/host_global_log.csv");
    global_log << "pktid,hopid,ttl,pint,xor\n";

    // --------------------------
    // Global receive/respond loop
    // --------------------------
    std::cout << "[host] Entering global receive/respond loop...\n";

    // Use a static buffer to avoid repeated allocations
    static uint8_t rx_buffer[2048];
    
    while (!all_done(done)) {
        printf("[host] Waiting to receive a frame...\n");
        ssize_t n = recv(sockfd, rx_buffer, sizeof(rx_buffer), 0);
        printf("[host] Received %zd bytes\n", n);
        if (n < 0) {
            perror("[host] recv failed");
            continue;
        }
        if (n == 0) continue;

        size_t frame_size = static_cast<size_t>(n);
        if (frame_size < sizeof(ethernet_h) + sizeof(ipv4_h) + sizeof(recipe_h)) {
            printf("[host] Received frame too small, ignoring\n");
            continue;
        }

        auto* rx_eth = reinterpret_cast<ethernet_h*>(rx_buffer);
        if (ntohs(rx_eth->ether_type) != 0x0800) {
            printf("[host] Received non-IPv4 frame, ignoring\n");
            continue;
        }

        auto* rx_ip = reinterpret_cast<ipv4_h*>(
            rx_buffer + sizeof(ethernet_h));
        if (rx_ip->protocol != 146) {
            printf("[host] Received non-recipe IP packet, ignoring\n");
            continue;
        }

        auto* rx_rec = reinterpret_cast<recipe_h*>(
            rx_buffer + sizeof(ethernet_h) + sizeof(ipv4_h));

        uint16_t rx_pktid = ntohs(rx_ip->identification);
        if (rx_pktid == 0 || rx_pktid > NUM_PACKETS) {
            continue;
        }

        uint8_t  ttl     = rx_ip->ttl;
        int      hopid   = 255 - ttl;
        uint16_t pint    = ntohs(rx_rec->pint);
        uint8_t  xor_deg = rx_rec->xor_degree;

        printf("[host] recv pktid=%u hopid=%d ttl=%u pint=%u xor=%u\n",
               rx_pktid, hopid, ttl, pint, xor_deg);

        // save info to logs
        global_log << rx_pktid << "," << hopid << ","
                   << static_cast<int>(ttl) << "," << pint << ","
                   << static_cast<int>(xor_deg) << "\n";

        // Stop echoing this pktid once TTL is 0 or hopid >= MAX_ITER
        if (ttl == 0 || hopid >= MAX_ITER) {
            done[rx_pktid] = true;
            printf("[host] Marking pktid=%u as done\n", rx_pktid);
            continue;
        }

        std::memcpy(rx_eth->dst, tofino_mac, 6);
        std::memcpy(rx_eth->src, host_mac, 6);

        struct sockaddr_ll addr{};
        addr.sll_family  = AF_PACKET;
        addr.sll_ifindex = ifindex;
        addr.sll_halen   = ETH_ALEN;
        std::memcpy(addr.sll_addr, tofino_mac, 6);

        printf("[host] Sending frame back to switch...\n");
        if (sendto(sockfd, rx_buffer, frame_size, 0,
                   reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
            perror("[host] sendto failed");
        }

    }

    printf("[host] All packets done, exiting\n");

    close(sockfd);
    return 0;
}
