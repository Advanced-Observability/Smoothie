/*

*/

#define REGISTER_SIZE 8192
#define TIMESTAMP_WIDTH 48
#define ID_WIDTH 16

control Flowlet(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

	//register<bit<ID_WIDTH>>(REGISTER_SIZE) flowlet_to_id;
    register<bit<TIMESTAMP_WIDTH>>(REGISTER_SIZE) flowlet_time_stamp;
    register <bit<48>>(REGISTER_SIZE) feedback_ts;

    action read_flowlet_registers(){
        bit<128> ip_src;
        bit<128> ip_dst;

    	if (hdr.ipv4.isValid()){
    		ip_src = (bit<128>) hdr.ipv4.srcAddr;
            ip_dst = (bit<128>) hdr.ipv4.dstAddr;
    	} else {
    		ip_src = hdr.ipv6.src_addr;
            ip_dst = hdr.ipv6.dst_addr;
    	}

        //compute register index
        hash(meta.register_index, HashAlgorithm.crc16,
            (bit<16>)0,
            { ip_src, ip_dst, meta.layer34_metadata.l4_src, meta.layer34_metadata.l4_dst, meta.layer34_metadata.l4_proto},
            (bit<14>)8192);

        @atomic {
            //Read previous time stamp
            flowlet_time_stamp.read(meta.flowlet_last_stamp, (bit<32>)meta.register_index);

            //Update timestamp
            flowlet_time_stamp.write((bit<32>)meta.register_index, standard_metadata.ingress_global_timestamp);
            feedback_ts.read(meta.feedback_ts, (bit<32>)meta.register_index);
        }

        //Read previous flowlet id
        //flowlet_to_id.read(meta.flowlet_id, (bit<32>)meta.flowlet_register_index);



    }

    action update_path(){
       meta.update_path = 1;
    }

    action set_timeout(bit<48> timeout){
        meta.flowlet_timeout = timeout;
    }
    
    // table used to activate flow monitoring for an egress port of the switch
    table tb_activate_flow_dest {
        actions = {
            set_timeout;
        }
        key = {
            standard_metadata.egress_spec: exact;
        }
        size = 255;
    }

    apply {

        if (!tb_activate_flow_dest.apply().hit) return;

        meta.update_path = 0;
        
        read_flowlet_registers();

        bit<48> flowlet_time_diff = standard_metadata.ingress_global_timestamp - meta.flowlet_last_stamp;
        //log_msg("last time: {}", {meta.flowlet_last_stamp});
        
        //check if inter-packet gap is > FLOWLET_TIMEOUT
        if (flowlet_time_diff > meta.flowlet_timeout){
            bit<48> backoff;
            random(backoff, 48w500000, 48w1000000);
            if ((standard_metadata.ingress_global_timestamp - meta.feedback_ts) > backoff){// avoid changing path too often and allow queue to discharge
                @atomic {
                    feedback_ts.write((bit<32>)meta.register_index, standard_metadata.ingress_global_timestamp);
                }
                update_path();
            }
        }
    }
}