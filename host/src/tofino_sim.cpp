// src/tofino_sim.cpp
#include "packet_format.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

constexpr uint16_t LISTEN_PORT = 9000;

// Simulate one pass through Tofino: modify IP + RECIPE in-place
void simulate_tofino_pass(std::vector<uint8_t>& buf) {
    if (buf.size() < sizeof(ipv4_h) + sizeof(recipe_h)) {
        std::cerr << "[sim] packet too short\n";
        return;
    }

    auto* ip  = reinterpret_cast<ipv4_h*>(buf.data());
    auto* rec = reinterpret_cast<recipe_h*>(buf.data() + sizeof(ipv4_h));

    uint8_t ttl_in = ip->ttl;
    if (ttl_in == 0) {
        std::cerr << "[sim] ttl is 0, dropping\n";
        return;
    }

    // meta.hop_count in your P4: 255 - ttl_in
    uint8_t hop_count = 255 - ttl_in;

    // Decrement TTL
    ip->ttl = ttl_in - 1;

    // Recompute checksum
    ip->hdr_checksum = 0;
    ip->hdr_checksum = ip_checksum(ip, sizeof(ipv4_h));

    // Simple RECIPE update: just to see evolving state
    uint16_t pint_host = ntohs(rec->pint);

    if ((rec->xor_degree % 2) == 0) {
        // "append" behavior: XOR with hop_count, increment xor_degree
        pint_host = static_cast<uint16_t>(pint_host ^ hop_count);
        rec->xor_degree += 1;
    } else {
        // "replace" behavior: set pint to hop_count, xor_degree = 1
        pint_host = static_cast<uint16_t>(hop_count);
        rec->xor_degree = 1;
    }

    rec->pint = htons(pint_host);
}

int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(LISTEN_PORT);

    if (bind(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    std::cout << "[sim] Tofino simulator listening on UDP port "
              << LISTEN_PORT << "\n";

    while (true) {
        std::vector<uint8_t> buf(2048);
        sockaddr_in src_addr{};
        socklen_t   src_len = sizeof(src_addr);

        ssize_t n = recvfrom(sockfd, buf.data(), buf.size(), 0,
                             reinterpret_cast<sockaddr*>(&src_addr),
                             &src_len);
        if (n < 0) {
            perror("[sim] recvfrom");
            continue;
        }
        buf.resize(static_cast<size_t>(n));

        std::cout << "[sim] Received " << n << " bytes\n";

        simulate_tofino_pass(buf);

        // Send back modified buffer to sender
        ssize_t sent = sendto(sockfd, buf.data(), buf.size(), 0,
                              reinterpret_cast<sockaddr*>(&src_addr),
                              src_len);
        if (sent < 0) {
            perror("[sim] sendto");
        } else {
            std::cout << "[sim] Sent back " << sent << " bytes\n";
        }
    }

    close(sockfd);
    return 0;
}