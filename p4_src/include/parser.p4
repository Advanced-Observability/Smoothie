/*
 */

error
{
	INTShimLenTooShort,
	INTVersionNotSupported
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
       transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.layer34_metadata.ip_src = hdr.ipv4.srcAddr;
        meta.layer34_metadata.ip_dst = hdr.ipv4.dstAddr;
        meta.layer34_metadata.ip_ver = 8w4;
        meta.layer34_metadata.dscp = hdr.ipv4.dscp;

        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        meta.ip_proto = hdr.ipv6.next_hdr;
        //meta.layer34_metadata.ip_src = hdr.ipv6.src_addr;
        //meta.layer34_metadata.ip_dst = hdr.ipv6.dst_addr;
        meta.layer34_metadata.ip_ver = 8w6;
        meta.layer34_metadata.dscp = hdr.ipv6.traffic_class;
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            IP_PROTO_SRV6: parse_srv6;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.layer34_metadata.l4_src = hdr.tcp.srcPort;
        meta.layer34_metadata.l4_dst = hdr.tcp.dstPort;
        meta.layer34_metadata.l4_proto = 8w0x6;
        transition select(meta.layer34_metadata.dscp) {
            DSCP_INT: parse_int;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        meta.layer34_metadata.l4_src = hdr.udp.srcPort;
        meta.layer34_metadata.l4_dst = hdr.udp.dstPort;
        meta.layer34_metadata.l4_proto = 8w0x11;
        transition select(meta.layer34_metadata.dscp, hdr.udp.dstPort) {
            (6w0x20 &&& 6w0x3f, 16w0x0 &&& 16w0x0): parse_int;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        meta.icmp_type = hdr.icmp.type;
        transition accept;
    }

        state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        meta.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition accept;
    }

    state parse_srv6 {
        packet.extract(hdr.srv6h);
        transition parse_srv6_list;
    }

    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        log_msg("Test:{} {}\n", {hdr.srv6h.segment_left, hdr.srv6_list.lastIndex});
        bool next_segment = (bit<32>)hdr.srv6h.segment_left - 1 == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            default: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        meta.next_srv6_sid = hdr.srv6_list.last.segment_id;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        // working with bit<8> and int<32> which cannot be cast directly; using
        // bit<32> as common intermediate type for comparision
        bool last_segment = (bit<32>)hdr.srv6h.last_entry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
           true: parse_srv6_next_hdr;
           false: parse_srv6_list;
        }
    }

    state parse_srv6_next_hdr {
        transition select(hdr.srv6h.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_int {
        packet.extract(hdr.int_shim);
        /*verify(hdr.int_shim.len >= 3, error.INTShimLenTooShort);*/
        packet.extract(hdr.int_header);
        // DAMU: warning (from TOFINO): Parser "verify" is currently unsupported
        /*verify(hdr.int_header.ver == INT_VERSION, error.INTVersionNotSupported);*/
        packet.extract(hdr.int_data, (bit<32>) (hdr.int_shim.len - 3)*32);
        transition accept;
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {

        // report headers
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_fixed_header);
        
        // original headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);

        //SRV6 headers
        packet.emit(hdr.srv6h);
        packet.emit(hdr.srv6_list);

        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);

        packet.emit(hdr.flowlet);
        
        // INT headers
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        
        // local INT node metadata
        packet.emit(hdr.int_switch_id);     //bit 1
        packet.emit(hdr.int_port_ids);       //bit 2
        packet.emit(hdr.int_hop_latency);   //bit 3
        packet.emit(hdr.int_q_occupancy);  // bit 4
        packet.emit(hdr.int_ingress_tstamp);  // bit 5
        packet.emit(hdr.int_egress_tstamp);   // bit 6
        packet.emit(hdr.int_level2_port_ids);   // bit 7
        packet.emit(hdr.int_egress_port_tx_util);  // bit 8

        //previous nodes int data
        packet.emit(hdr.int_data);

    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.id,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        
        update_checksum(
            hdr.report_ipv4.isValid(),
            {
                hdr.report_ipv4.version,
                hdr.report_ipv4.ihl,
                hdr.report_ipv4.dscp,
                hdr.report_ipv4.ecn,
                hdr.report_ipv4.totalLen,
                hdr.report_ipv4.id,
                hdr.report_ipv4.flags,
                hdr.report_ipv4.fragOffset,
                hdr.report_ipv4.ttl,
                hdr.report_ipv4.protocol,
                hdr.report_ipv4.srcAddr,
                hdr.report_ipv4.dstAddr
            },
            hdr.report_ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_ipv6_addr,
                hdr.ndp.type,
                hdr.ndp.length,
                hdr.ndp.target_mac_addr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
        
        /*update_checksum_with_payload(
            hdr.ipv4.isValid() && hdr.udp.isValid(), 
            {  hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr, 
                8w0, 
                hdr.ipv4.protocol, 
                hdr.udp.len, 
                hdr.udp.srcPort, 
                hdr.udp.dstPort,
                hdr.udp.len 
            }, 
            hdr.udp.csum, 
            HashAlgorithm.csum16
        ); 

        update_checksum_with_payload(
            hdr.ipv4.isValid() && hdr.udp.isValid() && hdr.int_header.isValid() , 
            {  hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr, 
                8w0, 
                hdr.ipv4.protocol, 
                hdr.udp.len, 
                hdr.udp.srcPort, 
                hdr.udp.dstPort, 
                hdr.udp.len,
                hdr.int_shim,
                hdr.int_header,
                hdr.int_switch_id,
                hdr.int_port_ids,
                hdr.int_q_occupancy,
                hdr.int_level2_port_ids,
                hdr.int_ingress_tstamp,
                hdr.int_egress_tstamp,
                hdr.int_egress_port_tx_util,
                hdr.int_hop_latency
            }, 
            hdr.udp.csum, 
            HashAlgorithm.csum16
        );

        update_checksum_with_payload(
            hdr.udp.isValid() && hdr.ipv6.isValid(),
            {   hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr, 
                hdr.udp.len, 
                hdr.udp.srcPort, 
                hdr.udp.dstPort,
                hdr.udp.len 
            },
            hdr.tcp.csum, HashAlgorithm.csum16);


        update_checksum_with_payload(
            hdr.tcp.isValid() && hdr.ipv4.isValid(),
            {   hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.tcpLen,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNum,
                hdr.tcp.ackNum,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.flags,
                hdr.tcp.winSize,
                hdr.tcp.urgPoint
            },
            hdr.tcp.csum, HashAlgorithm.csum16);*/

/*        update_checksum_with_payload(
            hdr.tcp.isValid() && hdr.ipv6.isValid(),
            {   hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                8w0,
                hdr.ipv6.next_hdr,
                meta.tcpLen,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNum,
                hdr.tcp.ackNum,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.flags,
                hdr.tcp.winSize,
                hdr.tcp.urgPoint
            },
            hdr.tcp.csum, HashAlgorithm.csum16);

        update_checksum_with_payload(
            hdr.tcp.isValid() && hdr.int_header.isValid() && hdr.ipv4.isValid(),
            {   hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.tcpLen,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNum,
                hdr.tcp.ackNum,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.flags,
                hdr.tcp.winSize,
                16w0,
                hdr.tcp.urgPoint,
                hdr.int_shim,
                hdr.int_header,
                hdr.int_switch_id,
                hdr.int_port_ids,
                hdr.int_q_occupancy,
                hdr.int_level2_port_ids,
                hdr.int_ingress_tstamp,
                hdr.int_egress_tstamp,
                hdr.int_egress_port_tx_util,
                hdr.int_hop_latency
            },
            hdr.tcp.csum, HashAlgorithm.csum16);*/
    }
}

