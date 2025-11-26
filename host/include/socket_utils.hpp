// include/socket_utils.hpp
#pragma once
#include <cstdint>
#include <string>
#include <vector>

int open_raw_socket(const std::string& ifname, int& ifindex_out);

bool send_frame(int sockfd,
                const std::vector<uint8_t>& frame,
                int ifindex,
                const uint8_t dst_mac[6]);

bool recv_frame(int sockfd, std::vector<uint8_t>& buffer);