// include/packet_format.hpp
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <arpa/inet.h>

#pragma pack(push, 1)

struct ethernet_h {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ether_type;
};


struct ipv4_h {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t identification;
    uint16_t flags_frag_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t hdr_checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct recipe_h {
    uint16_t pint;
    uint8_t  xor_degree;
};

#pragma pack(pop)

inline uint16_t ip_checksum(const void* vdata, size_t length) {
    const uint8_t* data = static_cast<const uint8_t*>(vdata);
    uint32_t acc = 0xffff;

    for (size_t i = 0; i + 1 < length; i += 2) {
        uint16_t word;
        std::memcpy(&word, data + i, sizeof(word));
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc = (acc & 0xffff) + (acc >> 16);
        }
    }

    if (length & 1) {
        uint16_t word = 0;
        std::memcpy(&word, data + length - 1, 1);
        acc += ntohs(word);
        if (acc > 0xffff) {
            acc = (acc & 0xffff) + (acc >> 16);
        }
    }

    acc = ~acc;
    return htons(static_cast<uint16_t>(acc));
}