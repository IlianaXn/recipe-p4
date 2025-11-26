// src/host_udp.cpp
#include "packet_format.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

constexpr const char* SIM_ADDR = "127.0.0.1";
constexpr uint16_t    SIM_PORT = 9000;

constexpr int NUM_PACKETS = 200;
constexpr int MAX_ITER    = 15;

static void ensure_output_directory() {
    struct stat st{};
    if (stat("output", &st) == -1) {
        mkdir("output", 0755);
        std::cout << "[host] Created output/ directory\n";
    }
}

int main() {
    ensure_output_directory();

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("[host] socket");
        return 1;
    }

    sockaddr_in sim_addr{};
    sim_addr.sin_family      = AF_INET;
    sim_addr.sin_port        = htons(SIM_PORT);
    sim_addr.sin_addr.s_addr = inet_addr(SIM_ADDR);

    sockaddr_in local_addr{};
    local_addr.sin_family      = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port        = htons(0);
    if (bind(sockfd, reinterpret_cast<sockaddr*>(&local_addr),
             sizeof(local_addr)) < 0) {
        perror("[host] bind");
        close(sockfd);
        return 1;
    }

    uint32_t src_ip = inet_addr("10.0.0.1");
    uint32_t dst_ip = inet_addr("10.0.0.2");

    for (int p = 1; p <= NUM_PACKETS; ++p) {
        uint16_t pktid = static_cast<uint16_t>(p);

        ipv4_h ip{};
        ip.version_ihl       = (4 << 4) | 5;
        ip.tos               = 0;

        uint16_t ip_total_len = sizeof(ipv4_h) + sizeof(recipe_h);
        ip.total_len          = htons(ip_total_len);

        ip.identification    = htons(pktid);
        ip.flags_frag_offset = htons(0x4000);
        ip.ttl               = 255;
        ip.protocol          = 146;
        ip.hdr_checksum      = 0;
        ip.src_addr          = src_ip;
        ip.dst_addr          = dst_ip;
        ip.hdr_checksum      = ip_checksum(&ip, sizeof(ipv4_h));

        recipe_h rec{};
        rec.pint       = htons(0);
        rec.xor_degree = 0;

        std::vector<uint8_t> buf(sizeof(ipv4_h) + sizeof(recipe_h));
        std::memcpy(buf.data(), &ip, sizeof(ipv4_h));
        std::memcpy(buf.data() + sizeof(ipv4_h), &rec, sizeof(recipe_h));

        std::cout << "[host] === Packet " << pktid << " start (ttl=255) ===\n";

        std::string fname = std::string("output/packet_") +
                            std::to_string(pktid) + ".csv";
        std::ofstream packet_log(fname);
        if (!packet_log) {
            std::cerr << "[host] Failed to open " << fname << "\n";
            close(sockfd);
            return 1;
        }
        packet_log << "hopid,ttl,pint,xor_degree\n";

        for (int iter = 1; iter <= MAX_ITER; ++iter) {
            ssize_t sent = sendto(sockfd, buf.data(), buf.size(), 0,
                                  reinterpret_cast<sockaddr*>(&sim_addr),
                                  sizeof(sim_addr));
            if (sent < 0) {
                perror("[host] sendto");
                break;
            }

            std::vector<uint8_t> rx(2048);
            sockaddr_in from_addr{};
            socklen_t from_len = sizeof(from_addr);
            ssize_t n = recvfrom(sockfd, rx.data(), rx.size(), 0,
                                 reinterpret_cast<sockaddr*>(&from_addr),
                                 &from_len);
            if (n < 0) {
                perror("[host] recvfrom");
                break;
            }
            rx.resize(n);

            if (rx.size() < sizeof(ipv4_h) + sizeof(recipe_h)) {
                std::cerr << "[host] Packet too short\n";
                break;
            }

            auto* rx_ip  = reinterpret_cast<ipv4_h*>(rx.data());
            auto* rx_rec = reinterpret_cast<recipe_h*>(rx.data() + sizeof(ipv4_h));

            uint8_t ttl      = rx_ip->ttl;
            uint16_t pint    = ntohs(rx_rec->pint);
            uint8_t xor_deg  = rx_rec->xor_degree;
            int hopid        = 255 - ttl;

            std::cout << "[host] pktid=" << pktid
                      << " iter=" << iter
                      << " ttl=" << (int)ttl
                      << " hopid=" << hopid
                      << " pint=" << pint
                      << " xor=" << (int)xor_deg << "\n";

            packet_log << hopid << "," << (int)ttl << ","
                       << pint << "," << (int)xor_deg << "\n";

            if (ttl == 0 || hopid >= MAX_ITER) {
                std::cout << "[host] stopping pktid=" << pktid << "\n";
                break;
            }

            buf = rx;
        }

        packet_log.close();
    }

    close(sockfd);
    return 0;
}