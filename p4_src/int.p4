/*
 */

/////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <core.p4>
#include <v1model.p4>
#include "include/headers.p4"
#include "include/parser.p4"
#include "include/int_source.p4"
#include "include/int_transit.p4"
#include "include/int_sink.p4"
#include "include/srv6.p4"
#include "include/flowlet.p4"

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t ig_intr_md) {
	

	action ipv4_forward (bit<48> dstAddr, bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        ig_intr_md.egress_spec = port;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {hdr.ipv4.dstAddr:lpm;}
        actions = {
            ipv4_forward;
            NoAction;
        }
        size=256;
        default_action=NoAction;
    }

    action drop() {
        mark_to_drop(ig_intr_md);
    }


    // --- l2_exact_table (for unicast entries) --------------------------------

    action set_egress_port(port_num_t port_num) {
        ig_intr_md.egress_spec = port_num;
    }

    table l2_exact_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egress_port;
            drop;
            NoAction;
        }
        const default_action = NoAction;
        @name("l2_exact_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- l2_ternary_table (for broadcast/multicast entries) ------------------

    action set_multicast_group(mcast_group_id_t gid) {
        if(hdr.ipv6.isValid()) hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
        ig_intr_md.mcast_grp = gid;
        meta.is_multicast = true;
    }

    table l2_ternary_table {
        key = {
            hdr.ethernet.dstAddr: ternary;
        }
        actions = {
            set_multicast_group;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
        @name("l2_ternary_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }


    // --- ndp_reply_table -----------------------------------------------------

   /* action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.srcAddr = target_mac;
        hdr.ethernet.dstAddr = IPV6_MCAST_01;
        ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp.length = 1;
        hdr.ndp.target_mac_addr = target_mac;
        ig_intr_md.egress_spec = ig_intr_md.ingress_port;
    }

    table ndp_reply_table {
        key = {
            hdr.ndp.target_ipv6_addr: exact;
        }
        actions = {
            ndp_ns_to_na;
        }
        @name("ndp_reply_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }*/

    // --- routing_v6_table ----------------------------------------------------


    action ecmp_group(bit<14> ecmp_group_id, bit<16> num_nhops){
        hash(meta.ecmp_metadata.ecmp_hash,
        HashAlgorithm.crc16,
        (bit<1>)0,
        { hdr.ipv6.src_addr,
          hdr.ipv6.dst_addr,
          meta.layer34_metadata.l4_src,
          meta.layer34_metadata.l4_dst,
          hdr.ipv6.next_hdr},
        num_nhops);

        meta.ecmp_metadata.ecmp_group_id = ecmp_group_id;
    }

    action ipv6_forward (bit<48> dstAddr, bit<9> port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        ig_intr_md.egress_spec = port;
        //hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }


    table ecmp_group_to_nhop {
        key = {
            meta.ecmp_metadata.ecmp_group_id:    exact;
            meta.ecmp_metadata.ecmp_hash: exact;
        }
        actions = {
            drop;
            ipv6_forward;
        }
        size = 1024;
    }

    table ipv6_lpm {
        key = {hdr.ipv6.dst_addr:lpm;}
        actions = {
            ipv6_forward;
            ecmp_group;
            NoAction;
        }
        size=256;
        default_action=NoAction;
    }

	apply {

        if (hdr.ipv4.isValid()) ipv4_lpm.apply();

        //if (hdr.ipv6.isValid() && my_station_table.apply().hit) {

        if (hdr.udp.isValid() || hdr.tcp.isValid()) {
            // in case of INT source port add main INT headers
            Int_source.apply(hdr, meta, ig_intr_md);
        }

        if (hdr.ipv6.isValid()){
            SRv6.apply(hdr, meta, ig_intr_md);
            switch (ipv6_lpm.apply().action_run){
                ecmp_group: {
                    ecmp_group_to_nhop.apply();
                }
            }
            if(hdr.ipv6.hop_limit == 0) { drop(); }
        }

        if (!l2_exact_table.apply().hit) {
            l2_ternary_table.apply();
            if(meta.is_multicast && hdr.ipv6.hop_limit < 252){mark_to_drop(ig_intr_md);}//drop multicast packet
        }

        if (hdr.udp.isValid() || hdr.tcp.isValid()){
            // in case of sink node make packet clone I2E in order to create INT report
            // which will be send to INT reporting port
            Int_sink_config.apply(hdr, meta, ig_intr_md);
        }

        Flowlet.apply(hdr, meta, ig_intr_md);
	}
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t eg_intr_md) {

    table host_port {
        key = {
            eg_intr_md.egress_port: exact;    
        }
        actions = {
            NoAction;
        }
        size=256;
        default_action=NoAction;
    }

	apply {

        //log_msg("Q depth: {}", {eg_intr_md.enq_qdepth});

        if (host_port.apply().hit && hdr.ipv6.isValid()) hdr.ipv6.hop_limit = 255;

        if (meta.is_multicast == true &&
            eg_intr_md.ingress_port == eg_intr_md.egress_port) {
            mark_to_drop(eg_intr_md);
        }

		Int_transit.apply(hdr, meta, eg_intr_md);
		Int_sink.apply(hdr, meta, eg_intr_md);

        /*if(hdr.tcp.isValid() && hdr.ipv4.isValid()) meta.tcpLen = hdr.ipv4.totalLen - (bit<16>)(hdr.ipv4.ihl)*4;
        if(hdr.tcp.isValid() && hdr.ipv6.isValid()) meta.tcpLen = hdr.ipv6.payload_len;*/
	}
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;





