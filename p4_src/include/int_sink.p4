 /*
 * Copyright 2020-2021 PSNC, FBK
 *
 * Author: Damian Parniewicz, Damu Ding
 *
 * Created in the GN4-3 project.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "int_report.p4"

const bit<32> INT_REPORT_MIRROR_SESSION_ID = 1;   // mirror session specyfing egress_port for cloned INT report packets, defined by switch CLI command   

control Int_sink_config(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action configure_sink(bit<16> sink_reporting_port) {
        meta.int_metadata.remove_int = 1;   // indicate that INT headers must be removed in egress
        meta.int_metadata.sink_reporting_port = (bit<16>)sink_reporting_port;
        //log_msg("packet ready to be cloned");
        clone_preserving_field_list(CloneType.I2E, INT_REPORT_MIRROR_SESSION_ID, CLONE_FL_1);
        //clone3<metadata>(CloneType.I2E, INT_REPORT_MIRROR_SESSION_ID, meta);
    }

    //table used to activate INT sink for particular egress port of the switch
    table tb_int_sink {
        actions = {
            configure_sink;
        }
        key = {
            standard_metadata.egress_spec: exact;
        }
        size = 255;
    }
    
    apply {
       // INT sink must process only INT packets
        if (hdr.int_header.isValid())
            tb_int_sink.apply();
    }
}

control Int_sink(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action remove_sink_header() {
        // restore original headers
        bit<16> len_bytes = ((bit<16>)hdr.int_shim.len) << 2;
        if(hdr.ipv4.isValid()){
            hdr.ipv4.dscp = hdr.int_shim.dscp;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen - len_bytes;
        } else {
            hdr.ipv6.traffic_class = hdr.int_shim.dscp;
            hdr.ipv6.payload_len = hdr.ipv6.payload_len - len_bytes;
        }

        
        if (hdr.udp.isValid()) {
            hdr.udp.len = hdr.udp.len - len_bytes;
        }

        hdr.int_data.setInvalid();

        // remove INT data added in INT sink
        hdr.int_switch_id.setInvalid();
        hdr.int_port_ids.setInvalid();
        hdr.int_ingress_tstamp.setInvalid();
        hdr.int_egress_tstamp.setInvalid();
        hdr.int_hop_latency.setInvalid();
        hdr.int_level2_port_ids.setInvalid();
        hdr.int_q_occupancy.setInvalid();
        hdr.int_egress_port_tx_util.setInvalid();
        
        // remove int data
        hdr.int_shim.setInvalid();
        hdr.int_header.setInvalid();

        //log_msg("cool");
    }

    apply {
        // INT sink must process only INT packets
        if (!hdr.int_header.isValid())
            return;

        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_NORMAL && meta.int_metadata.remove_int == 1) {
            // remove INT headers from a frame
            remove_sink_header();
        }
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
            // prepare an INT report for the INT collector
            Int_report.apply(hdr, meta, standard_metadata);
        }

    }
}
