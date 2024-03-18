/*
 */
 
#ifndef _HEADERS_P4_
#define _HEADERS_P4_

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6

#define SRV6_MAX_HOPS 4

typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<16>  mcast_group_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16>  l4_port_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;

const bit<8> IP_PROTO_ICMP   = 1;
const bit<8> IP_PROTO_TCP    = 6;
const bit<8> IP_PROTO_UDP    = 17;
const bit<8> IP_PROTO_SRV6   = 43;
const bit<8> IP_PROTO_ICMPV6 = 58;

const mac_addr_t IPV6_MCAST_01 = 0x33_33_00_00_00_01;

const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;

const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;

const bit<32> NDP_FLAG_ROUTER    = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;
const bit<32> NDP_FLAG_OVERRIDE  = 0x20000000;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> totalLen;
    bit<16> id;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>    version;
    bit<6>    traffic_class;
    bit<2>    ecn;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr;
    bit<8>    hop_limit;
    bit<128>  src_addr;
    bit<128>  dst_addr;
}

header srv6h_t {
    bit<8>   next_hdr;
    bit<8>   hdr_ext_len;
    bit<8>   routing_type;
    bit<8>   segment_left;
    bit<8>   last_entry;
    bit<8>   flags;
    bit<16>  tag;
}

header srv6_list_t {
    bit<128>  segment_id;
}

header icmp_t {
    bit<8>   type;
    bit<8>   icmp_code;
    bit<16>  checksum;
    bit<16>  identifier;
    bit<16>  sequence_number;
    bit<64>  timestamp;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_t {
    bit<32>      flags;
    ipv6_addr_t  target_ipv6_addr;
    // NDP option.
    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> csum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNum;
    bit<32> ackNum;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> winSize;
    bit<16> csum;
    bit<16> urgPoint;
}

const bit<6> DSCP_INT = 0x20;   // indicates an INT header in the packet
const bit<16> INT_SHIM_HEADER_LEN_BYTES = 4;
const bit<8> INT_TYPE_HOP_BY_HOP = 1;

header intl4_shim_t {
    bit<8> int_type;
    bit<8> rsvd1;
    bit<8> len;    // the length of all INT headers in 4-byte words
    bit<6> dscp;  // copy DSCP here
    bit<2> rsvd3;
}

const bit<16> INT_HEADER_LEN_BYTES = 8;
const bit<4> INT_VERSION = 1;

header int_header_t {
    bit<4>  ver;
    bit<2>  rep;
    bit<1>  c;
    bit<1>  e;
    bit<1>  m;
    bit<7>  rsvd1;
    bit<3>  rsvd2;
    bit<5>  hop_metadata_len;   // the length of the metadata added by a single INT node (4-byte words)
    bit<8>  remaining_hop_cnt;  // how many switches can still add INT metadata
    bit<16> instruction_mask;   
    bit<16> rsvd3;
}

const bit<16> INT_ALL_HEADER_LEN_BYTES = INT_SHIM_HEADER_LEN_BYTES + INT_HEADER_LEN_BYTES;

header int_switch_id_t {
    bit<32> switch_id;
}

header int_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

header int_hop_latency_t {
    bit<32> hop_latency;
}

header int_q_occupancy_t {
    bit<8>  q_id;
    bit<1> trend;
    bit<23> q_occupancy;
}

header int_ingress_tstamp_t {
    bit<64> ingress_tstamp;
}

header int_egress_tstamp_t {
    bit<64> egress_tstamp;
}

header int_level2_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}

header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}


const bit<4> INT_REPORT_HEADER_LEN_WORDS = 4;
const bit<4> INT_REPORT_VERSION = 1;

header int_report_fixed_header_t {
    bit<4> ver;
    bit<4> len;
    bit<3> nprot;
    bit<5> rep_md_bits_high; // Split rep_md_bits to align to word boundaries
    bit<1> rep_md_bits_low;
    bit<6> reserved;
    bit<1> d;
    bit<1> q;
    bit<1> f;
    bit<6> hw_id;
    bit<32> switch_id;
    bit<32> seq_num;
    bit<32> ingress_tstamp;
}

struct int_metadata_t {
    bit<1>  source;    // is INT source functionality enabled
    bit<1>  sink;        // is INT sink functionality enabled
    bit<32> switch_id;  // INT switch id is configured by network controller
    bit<16> insert_byte_cnt;  // counter of inserted INT bytes
    bit<8>  int_hdr_word_len;  // counter of inserted INT words
    bit<1>  remove_int;           // indicator that all INT headers and data must be removed at egress for the processed packet 
    bit<16> sink_reporting_port;    // on which port INT reports must be send to INT collector
    bit<64> ingress_tstamp;   // pass ingress timestamp from Ingress pipeline to Egress pipeline
    bit<16> ingress_port;  // pass ingress port from Ingress pipeline to Egress pipeline 
}

struct layer34_metadata_t {
    bit<32> ip_src;
    bit<32> ip_dst;
    bit<8>  ip_ver;
    bit<16> l4_src;
    bit<16> l4_dst;
    bit<8>  l4_proto;
    bit<16> l3_mtu;
    bit<6>  dscp;
}

struct ecmp_metadata_t {
    bit<14> ecmp_hash;
    bit<14> ecmp_group_id;
}

const bit<8> CLONE_FL_1  = 1;

struct metadata {
    @field_list(CLONE_FL_1)
    int_metadata_t       int_metadata;
    intl4_shim_t         int_shim;
    @field_list(CLONE_FL_1)
    layer34_metadata_t   layer34_metadata;
    ecmp_metadata_t      ecmp_metadata;
    bit<16>              tcpLen;
    @field_list(CLONE_FL_1)
    bool                 is_multicast;
    ipv6_addr_t          next_srv6_sid;
    bit<8>               ip_proto;
    bit<8>               icmp_type;

    bit<48> flowlet_last_stamp;

    bit<13> register_index;
    //bit<16> flowlet_id;
    bool flow_source;
    @field_list(CLONE_FL_1)
    bit<8> update_path;

    bit<8> proportion;
    bit<48> flowlet_timeout;
    bit<48> feedback_ts;
}

header int_data_t {
    // Enough room for previous 4 nodes worth of data
    varbit<1600> data;
}


header flowlet_t {
    bit<8> update_path;
}


struct headers {

    // INT report headers
    ethernet_t                report_ethernet;
    ipv4_t                    report_ipv4;
    udp_t                     report_udp;
    int_report_fixed_header_t report_fixed_header;
    
    // normal headers
    ethernet_t                ethernet;
    ipv4_t                    ipv4;
    ipv6_t                    ipv6;

    // SRV6 headers
    srv6h_t                   srv6h;
    srv6_list_t[SRV6_MAX_HOPS] srv6_list;

    // L4 headers
    tcp_t                     tcp;
    udp_t                     udp;
    icmp_t                    icmp;
    icmpv6_t                  icmpv6;
    ndp_t                     ndp;

    // INT headers
    intl4_shim_t              int_shim;
    int_header_t              int_header;
  
    // local INT node metadata
    int_egress_port_tx_util_t int_egress_port_tx_util;
    int_egress_tstamp_t       int_egress_tstamp;
    int_hop_latency_t         int_hop_latency;
    int_ingress_tstamp_t      int_ingress_tstamp;
    int_port_ids_t            int_port_ids;
    int_level2_port_ids_t     int_level2_port_ids;
    int_q_occupancy_t         int_q_occupancy;
    int_switch_id_t           int_switch_id;

    // INT metadata of previous nodes
    int_data_t                int_data;

    flowlet_t                 flowlet;
}


#endif
