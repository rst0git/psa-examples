/* -*- P4_16 -*- */
#include <core.p4>
#include <psa.p4>

typedef bit<48> EthernetAddress_t;
typedef bit<12> vlan_id_t;


const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_IP4  = 0x0800;
const bit<16> ETHERTYPE_VLAN = 0x8100;

const bit<8> IPPROTO_ICMP = 1;
const bit<8> IPPROTO_TCP  = 6;
const bit<8> IPPROTO_UDP  = 17;

header ethernet_t {
    EthernetAddress_t dst_addr;
    EthernetAddress_t src_addr;
    bit<16>           type;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlength;
    bit<8> plength;
    bit<16> opcode;
}

header vlan_t {
    bit<3> priority;
    bit<1> cfi; // Canonical format indicator
    vlan_id_t vlan_id; // VLAN identifier
    bit<16> eth_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8>  icmp_type;
    bit<8>  icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

header tcp_t {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct empty_metadata_t { }

struct metadata_t { }

struct headers_t {
    ethernet_t       ethernet;
    arp_t            arp;
    vlan_t           vlan;
    vlan_t           inner_vlan;
    ipv4_t           ipv4;
    icmp_t           icmp;
    tcp_t            tcp;
    udp_t            udp;
}

parser IngressParserImpl(packet_in packet,
                         out headers_t hdr,
                         inout metadata_t user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_metadata_t resubmit_meta,
                         in empty_metadata_t recirculate_meta)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.type) {
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IP4: parse_ipv4;
            ETHERTYPE_VLAN: parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.eth_type) {
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IP4: parse_ipv4;
            ETHERTYPE_VLAN: parse_inner_vlan;
            default: accept;
        }
    }

    state parse_inner_vlan {
        packet.extract(hdr.inner_vlan);
        transition select(hdr.inner_vlan.eth_type) {
            ETHERTYPE_ARP: parse_arp;
            ETHERTYPE_IP4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_TCP: parse_tcp;
            IPPROTO_UDP: parse_udp;
            IPPROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

control ingress(inout headers_t hdr,
                inout metadata_t user_meta,
                in    psa_ingress_input_metadata_t  istd,
                inout psa_ingress_output_metadata_t ostd)
{
    action drop() {
        ingress_drop(ostd);
    }

    action ipv4_forward(EthernetAddress_t dst_addr, PortId_t port) {
        hdr.ethernet.dst_addr = dst_addr;
        // FIXME: psa_switch doesn't support InternetChecksum yet
        // hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        send_to_port(ostd, port);
    }

    table ipv4_forward_table {
        key = {
            hdr.ipv4.dst_addr: lpm;
            hdr.vlan.vlan_id: exact;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action add_vlan(vlan_id_t vlan_id, bit<3> priority) {
        hdr.vlan.setValid();
        hdr.vlan.eth_type = hdr.ethernet.type;
        hdr.ethernet.type = ETHERTYPE_VLAN;
        hdr.vlan.vlan_id = vlan_id;
        hdr.vlan.priority = priority;
        hdr.vlan.cfi = 1;
    }

    table add_vlan_tag {
        key = {
            istd.ingress_port: exact;
        }
        actions = {
            add_vlan;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    action remove_vlan() {
        hdr.ethernet.type = hdr.vlan.eth_type;
        hdr.vlan.setInvalid();
    }

    table remove_vlan_tag {
        key = {
            ostd.egress_port: exact;
        }
        actions = {
            remove_vlan;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (!hdr.vlan.isValid()) {
            add_vlan_tag.apply();
        }

        if (hdr.ipv4.isValid()) {
            ipv4_forward_table.apply();
        }

        remove_vlan_tag.apply();
    }
}

parser EgressParserImpl(packet_in buffer,
                        out headers_t parsed_hdr,
                        inout metadata_t user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_metadata_t normal_meta,
                        in empty_metadata_t clone_i2e_meta,
                        in empty_metadata_t clone_e2e_meta)
{
    state start {
        transition accept;
    }
}

control egress(inout headers_t hdr,
               inout metadata_t user_meta,
               in    psa_egress_input_metadata_t  istd,
               inout psa_egress_output_metadata_t ostd)
{
    apply { }
}

control IngressDeparserImpl(packet_out packet,
                            out empty_metadata_t clone_i2e_meta,
                            out empty_metadata_t resubmit_meta,
                            out empty_metadata_t normal_meta,
                            inout headers_t hdr,
                            in metadata_t meta,
                            in psa_ingress_output_metadata_t istd)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.inner_vlan);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}

control EgressDeparserImpl(packet_out packet,
                           out empty_metadata_t clone_e2e_meta,
                           out empty_metadata_t recirculate_meta,
                           inout headers_t hdr,
                           in metadata_t meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan);
        packet.emit(hdr.inner_vlan);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}

IngressPipeline(IngressParserImpl(), ingress(), IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(), egress(), EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
