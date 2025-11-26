// src/socket_utils.cpp
#include "socket_utils.hpp"

#ifndef __linux__
#error "socket_utils.cpp requires Linux (AF_PACKET raw sockets). Build and run this on a Linux machine connected to Tofino."
#endif

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

int open_raw_socket(const std::string& ifname, int& ifindex_out) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }

    ifindex_out = ifr.ifr_ifindex;

    struct sockaddr_ll addr{};
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = ifindex_out;

    if (bind(sockfd, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

bool send_frame(int sockfd,
                const std::vector<uint8_t>& frame,
                int ifindex,
                const uint8_t dst_mac[6]) {
    struct sockaddr_ll addr{};
    addr.sll_family  = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen   = ETH_ALEN;
    std::memcpy(addr.sll_addr, dst_mac, 6);

    ssize_t sent = sendto(sockfd, frame.data(), frame.size(), 0,
                          reinterpret_cast<struct sockaddr*>(&addr),
                          sizeof(addr));
    if (sent < 0) {
        perror("sendto");
        return false;
    }
    return true;
}

bool recv_frame(int sockfd, std::vector<uint8_t>& buffer) {
    buffer.resize(2048);
    ssize_t n = recv(sockfd, buffer.data(), buffer.size(), 0);
    if (n <= 0) {
        perror("recv");
        return false;
    }
    buffer.resize(static_cast<size_t>(n));
    return true;
}