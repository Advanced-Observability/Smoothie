/*
 * Copyright 2020-2021 PSNC, FBK
 *
 * Author: Bartosz Krakowiak, Damu Ding
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

// Code adapted from:
// - https://github.com/baru64/int-p4/blob/master/int.p4app/p4src/int_report.p4

// register to store seq_num
register<bit<32>> (1) report_seq_num_register;

control Int_report(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

        bit<32> seq_num_value = 0;

        // INT Report structure
        // [Eth][IP][UDP][INT REPORT HDR][ETH][IP][UDP/TCP][INT SHIM][INT DATA]

        action send_report(bit<48> dp_mac, bit<32> dp_ip, bit<48> collector_mac, bit<32> collector_ip, bit<16> collector_port) {

            log_msg("Sending report\n");
            // Ethernet **********************************************************
            hdr.report_ethernet.setValid();
            hdr.report_ethernet.dstAddr = collector_mac;
            hdr.report_ethernet.srcAddr = dp_mac;
            hdr.report_ethernet.etherType = 0x0800;

            // IPv4 **************************************************************
            hdr.report_ipv4.setValid();
            hdr.report_ipv4.version = 4;
            hdr.report_ipv4.ihl = 5;
            hdr.report_ipv4.dscp = 0;
            hdr.report_ipv4.ecn = 0;

            if(hdr.ipv4.isValid()){
                // 2x ipv4 header (20*2) + udp header (8) + eth header (14) + report header (16) + int data len
                hdr.report_ipv4.totalLen = (bit<16>)(20 + 20 + 8 + 14)
                    + ((bit<16>)(INT_REPORT_HEADER_LEN_WORDS)<<2)
                    + (((bit<16>)hdr.int_shim.len) << 2);
            } else {
                // ipv4 header (20) + ipv6 header (40) + udp header (8) + eth header (14) + report header (16) + int data len
                hdr.report_ipv4.totalLen = (bit<16>)(20 + 40 + 8 + 14)
                    + ((bit<16>)(INT_REPORT_HEADER_LEN_WORDS)<<2)
                    + (((bit<16>)hdr.int_shim.len) << 2);
                if (hdr.ipv6.next_hdr == IP_PROTO_SRV6) {
                    hdr.report_ipv4.totalLen = hdr.report_ipv4.totalLen + 8 + (((bit<16>)hdr.srv6h.last_entry+1)*16);
                }
            }
                
            // add size of original tcp/udp header
            if (hdr.tcp.isValid()) {
                hdr.report_ipv4.totalLen = hdr.report_ipv4.totalLen
                    + (((bit<16>)hdr.tcp.dataOffset) << 2);

            } else {
                hdr.report_ipv4.totalLen = hdr.report_ipv4.totalLen + 8;
            }

            hdr.report_ipv4.id = 0;
            hdr.report_ipv4.flags = 0;
            hdr.report_ipv4.fragOffset = 0;
            hdr.report_ipv4.ttl = 64;
            hdr.report_ipv4.protocol = 17; // UDP
            hdr.report_ipv4.srcAddr = dp_ip;
            hdr.report_ipv4.dstAddr = collector_ip;

            // UDP ***************************************************************
            hdr.report_udp.setValid();
            hdr.report_udp.srcPort = 0;
            hdr.report_udp.dstPort = collector_port;
            hdr.report_udp.len = hdr.report_ipv4.totalLen - 20;

            // INT report fixed header ************************************************/
            // INT report version 1.0
            hdr.report_fixed_header.setValid();
            hdr.report_fixed_header.ver = INT_REPORT_VERSION;
            hdr.report_fixed_header.len = INT_REPORT_HEADER_LEN_WORDS;

            hdr.report_fixed_header.nprot = 0; // 0 for Ethernet
            hdr.report_fixed_header.rep_md_bits_high = 0;
            hdr.report_fixed_header.rep_md_bits_low = 0;
            hdr.report_fixed_header.reserved = 0;
            hdr.report_fixed_header.d = 0;
            hdr.report_fixed_header.q = 0;
            // f - indicates that report is for tracked flow, INT data is present
            hdr.report_fixed_header.f = 1;
            // hw_id - specific to the switch, e.g. id of linecard
            hdr.report_fixed_header.hw_id = 0;
            hdr.report_fixed_header.switch_id = meta.int_metadata.switch_id;
            report_seq_num_register.read(seq_num_value, 0);
            hdr.report_fixed_header.seq_num = seq_num_value;
            report_seq_num_register.write(0, seq_num_value + 1);

            hdr.report_fixed_header.ingress_tstamp = (bit<32>)standard_metadata.ingress_global_timestamp;

            hdr.flowlet.setValid();
            hdr.flowlet.update_path = meta.update_path;

            // Original packet headers, INT shim and INT data come after report header.
            // drop all data besides int report and report eth header
            truncate((bit<32>)hdr.report_ipv4.totalLen + 14 + 1);
        }

        table tb_int_reporting {
            actions = {
                send_report;
            }
            //size=512;
        }

        apply {
            tb_int_reporting.apply();
        }
    }
