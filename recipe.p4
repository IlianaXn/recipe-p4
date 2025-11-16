// This software is Copyright (c) 2024 Georgia Tech Research Corporation. All
// Rights Reserved. Permission to copy, modify, and distribute this software and
// its documentation for academic research and education purposes, without fee,
// and without a written agreement is hereby granted, provided that the above
// copyright notice, this paragraph and the following three paragraphs appear in
// all copies. Permission to make use of this software for other than academic
// research and education purposes may be obtained by contacting:
//
//  Office of Technology Licensing
//  Georgia Institute of Technology
//  926 Dalney Street, NW
//  Atlanta, GA 30318
//  404.385.8066
//  techlicensing@gtrc.gatech.edu
//
// This software program and documentation are copyrighted by Georgia Tech
// Research Corporation (GTRC). The software program and documentation are 
// supplied "as is", without any accompanying services from GTRC. GTRC does
// not warrant that the operation of the program will be uninterrupted or
// error-free. The end-user understands that the program was developed for
// research purposes and is advised not to rely exclusively on the program for
// any reason.
//
// IN NO EVENT SHALL GEORGIA TECH RESEARCH CORPORATION BE LIABLE TO ANY PARTY FOR
// DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
// LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION,
// EVEN IF GEORGIA TECH RESEARCH CORPORATION HAS BEEN ADVISED OF THE POSSIBILITY
// OF SUCH DAMAGE. GEORGIA TECH RESEARCH CORPORATION SPECIFICALLY DISCLAIMS ANY
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED
// HEREUNDER IS ON AN "AS IS" BASIS, AND  GEORGIA TECH RESEARCH CORPORATION HAS
// NO OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
// MODIFICATIONS.

#include <core.p4>
#include <tna.p4>

#include "./include/constants.p4"
#include "./include/headers.p4"

parser IngressParser(packet_in        pkt,
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);

        meta.hop_count = 0;
        meta.idx = 0;
        meta.hash_id = 0;
        transition parse_ethernet;
    }
    
    state parse_ethernet {       
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            0x8100 &&& 0xEFFF : parse_vlan_tag;
            ether_type_t.IPV4 : parse_ipv4;
            ether_type_t.IPV6 : parse_ipv6;
            default : accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan.next);
        transition select(hdr.vlan.last.ether_type) {
            0x8100: parse_vlan_tag;
            ether_type_t.IPV4 : parse_ipv4;
            ether_type_t.IPV6 : parse_ipv6;
            default: reject;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            ip_protocol_t.RECIPE: parse_recipe;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            ip_protocol_t.RECIPE: parse_recipe;
            default: accept;
        }
    }

    state parse_recipe {
        pkt.extract(hdr.recipe);
        transition accept;
    }
}

control Ingress(
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{      
    action drop_exit_ingress () {
        ig_dprsr_md.drop_ctl = 1;
        exit;
    }

    action set_mirror_port() {
        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action compute_base() {
        meta.idx = (bit<16>) meta.hop_count * MAX_DEGREE;
    }

    Register<bit<32>, bit<16>>(GLOBAL_TABLE_ENTRIES, 0) probs_a;
    RegisterAction<bit<32>, bit<16>, bit<32>>(probs_a)
    read_probs_a = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
        }
    };

    Register<bit<32>, bit<16>>(GLOBAL_TABLE_ENTRIES, 0) probs_r;
    RegisterAction<bit<32>, bit<16>, bit<32>>(probs_r)
    read_probs_r = {
        void apply(inout bit<32> value, out bit<32> rv) {
            rv = value;
        }
    };

    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_v4;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_v6;


    apply {
        // find the switch id (hop) in the path
        if (hdr.ipv4.isValid()){
            meta.hop_count = 255 - hdr.ipv4.ttl;
        }
        else if (hdr.ipv6.isValid()){
            meta.hop_count = 255 - hdr.ipv6.hop_limit;
        }
        // recipe header
        if (!hdr.recipe.isValid()){
            drop_exit_ingress();
        }
        if (hdr.ipv4.isValid()){
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            meta.hash_id = hash_v4.get({
                        hdr.ipv4.src_addr,
                        hdr.ipv4.dst_addr,
                        hdr.ipv4.protocol,
                        hdr.ipv4.identification,
                        meta.hop_count
            });
        }
        else if (hdr.ipv6.isValid()){
            hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
            meta.hash_id = hash_v6.get({
                        hdr.ipv6.src_addr[127:96],
                        hdr.ipv6.src_addr[95:64],
                        hdr.ipv6.src_addr[63:32],
                        hdr.ipv6.src_addr[31:0],
                        hdr.ipv6.dst_addr[127:96],
                        hdr.ipv6.dst_addr[95:64],
                        hdr.ipv6.dst_addr[63:32],
                        hdr.ipv6.dst_addr[31:0],
                        hdr.ipv6.next_hdr,
                        meta.hop_count
            });
        }
        set_mirror_port();
        bit<32> a_prob;
        bit<32> r_prob;
        bit<16> row;
        bit<16> column;
        bit<16> idx;

        compute_base();
        meta.idx = meta.idx + (bit<16>) hdr.recipe.xor_degree;
        a_prob = read_probs_a.execute(idx);
        r_prob = read_probs_r.execute(idx);
        if (!hdr.recipe.isValid()){
            hdr.recipe.setValid();
            hdr.recipe.pint = 0;
            hdr.recipe.xor_degree = 0;
        }
        if (meta.hash_id - a_prob < 0){
            hdr.recipe.pint = hdr.recipe.pint ^ (bit<16>) meta.hop_count;
            hdr.recipe.xor_degree = hdr.recipe.xor_degree + 1;
        }
        else if (meta.hash_id - a_prob - r_prob < 0){
            hdr.recipe.pint = (bit<16>) meta.hop_count;
            hdr.recipe.xor_degree = 1;
        }
    }
}

control IngressDeparser(packet_out pkt,
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

parser EgressParser(packet_in        pkt,
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ether_type_t.IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

}

control Egress(
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {}
}

control EgressDeparser(packet_out pkt,
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Checksum() ipv4_checksum;
    apply {

        if (hdr.ipv4.isValid())
        {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.tos,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }

        pkt.emit(hdr);
    }
}

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;