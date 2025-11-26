typedef bit<48> mac_addr_t;
typedef bit<8> header_type_t;

enum bit<16> ether_type_t {
    IPV4 = 0x0800,
    IPV6 = 0x86DD
}

header ethernet_h {
    mac_addr_t   dst_addr;
    mac_addr_t   src_addr;
    ether_type_t ether_type;
}

header vlan_h {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    ether_type_t ether_type;
}

typedef bit<32> ipv4_addr_t;
typedef bit<128> ipv6_addr_t;

enum bit<8> ip_protocol_t{
    UDP = 17, 
    TCP = 6,
    RECIPE = 146 // custom protocol number for RECIPE
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    ip_protocol_t protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_len;
    ip_protocol_t next_hdr;
    bit<8> hop_limit;
    ipv6_addr_t src_addr;
    ipv6_addr_t dst_addr;
}


header recipe_h {
    bit<16> switch_id;
    bit<16> pint;
    bit<8> xor_degree;
}

struct my_ingress_metadata_t {
    bit<16> idx;
    bit<8> hop_count;
    bit<32> hash_id;
    bit<32> a_prob;
    bit<32> r_prob;
    bit<32> res;
}

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    vlan_h[3]       vlan;
    ipv4_h       ipv4;
    ipv6_h       ipv6;
    recipe_h        recipe;
}

struct my_egress_metadata_t {
}

struct my_egress_headers_t {
    ethernet_h ethernet;
    ipv4_h     ipv4;
    ipv6_h     ipv6;
    recipe_h recipe;
}

