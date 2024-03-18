import argparse
import time
import socket
import struct
import binascii
import pprint
import logging
import hashlib
from copy import copy, deepcopy
import io
#from influxdb import InfluxDBClient
from ipaddress import IPv6Address
from p4utils.utils.helper import *
import networkx as nx
#import matplotlib
import random
from helper import *
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
from p4utils.utils.thrift_API import UIn_Error
from p4utils.utils.helper import load_topo
import signal
import sys

import pickle

queue_size = 256
log_format = "[%(asctime)s] [%(levelname)s] - %(message)s"
logging.basicConfig(level=logging.ERROR, format=log_format, filename="log/int_collector.log")
logger = logging.getLogger('int_collector')

# flaps = {}

# def signal_handler(sig, frame):
#     with open('flap.pkl', 'wb') as handle:
#         pickle.dump(flaps, handle)
#     sys.exit(0)

# signal.signal(signal.SIGTERM, signal_handler)


def parse_params():
    parser = argparse.ArgumentParser(description='InfluxDB INTCollector client.')

    parser.add_argument("-i", "--int_port", default=54321, type=int,
        help="Destination port of INT Telemetry reports")

    parser.add_argument("-c", "--conf", default="./p4app.json", type=str,
        help="Network description Json file")

    parser.add_argument("-H", "--host", default="localhost",
        help="InfluxDB server address")

    parser.add_argument("-D", "--database", default="int_telemetry_db",
        help="Database name")

    parser.add_argument("-p", "--period", default=1, type=int,
        help="Time period to push data in normal condition")

    parser.add_argument("-d", "--debug_mode", default=0, type=int,
        help="Set to 1 to print debug information")

    return parser.parse_args()

def hash_list(flow):
    flow_string = "".join([str(x) for x in flow])
    flow_hash = hashlib.md5(flow_string.encode())
    return flow_hash.hexdigest()


class path_infos(object):
    def __init__(self, size=10):
        self.index = 0
        self.len = 0
        self.size = size
        self.weights = [None] * size
        self.times = [0] * size
        self.time_elapsed = 0
        self.last_t = self.first_t = 0
    
    def get_len(self):
        return self.len

    def linreg(self):
        """
        return a,b in solution to y = ax + b such that root mean square distance between trend line and original points is minimized
        """
        X = range(self.get_len())
        Y = [x for _, x in sorted(zip(self.times[:len(X)], self.weights[:len(X)]))]
        # print(Y)

        N = len(X)
        Sx = Sy = Sxx = Syy = Sxy = 0.0
        for x, y in zip(X, Y):
            Sx = Sx + x
            Sy = Sy + y
            Sxx = Sxx + x*x
            Syy = Syy + y*y
            Sxy = Sxy + x*y
        det = Sxx * N - Sx * Sx
        if det == 0: return 0
        return (Sxy * N - Sy * Sx)/det, (Sxx * Sy - Sx * Sxy)/det

    def add_weight(self, w, t):
        self.weights[self.index] = w
        self.times[self.index] = t
        self.last_t = t
        if self.len == 0:
            self.first_t = t
        elif self.len == self.size:
            self.first_t = self.times[(self.index+1)%self.size]
        self.index = (self.index + 1)%self.size
        self.len = min([self.len+1, self.size])

class NetGraph(object):
    def __init__(self):
        self.G = load_topo('topology.json')
        self.max_bw = 0 #used to normalize link capacity between [0, 1]
        self.delta = 0.001
        self.detour = 0
        self.flows = {}
        self.paths = {}
        self.path_infos = {}

        self.hosts = [x for x in self.G.nodes if self.G.isHost(x)]

        self.switches = [x for x in self.G.nodes if self.G.isP4Switch(x)]

        self.thrift_switches = [None] * len(self.switches)

        for link in list(self.G.edges(data=True)):
            node1 = link[0]
            node2 = link[1]

            if self.G.node_to_node_interface_bw(node1, node2) > self.max_bw:
                self.max_bw = self.G.node_to_node_interface_bw(node1, node2)
            link[2][node1+"weight"] = 0
            link[2][node2+"weight"] = 0


        #nx.draw(self.G)
        #matplotlib.pyplot.show()

    def store_flow_path(self, flow, path):
        key = hash_list(flow)
        value = hash_list(path)
        if key in self.flows:
            self.flows[key][0] = value
        else:
            self.flows[key] = [value]

    def get_path_digest(self, flow):
        key = hash_list(flow)
        if key in self.flows:
            return self.flows[key][0]
        else:
            return ""
            

    def update_infos(self, report):
        #start_time = time.time()
        key = hash_list(report.flow_id.values())
        # if key not in flaps:
        #     flaps[key] = 0
        dst = src = 0
        queue_load = 0
        current_path = []
        src_host = self.G.get_host_name(ipv6_to_v4(report.flow_id["srcip"]))
        dst_host = self.G.get_host_name(ipv6_to_v4(report.flow_id["dstip"]))
        src_node = None
        dst_node = None
        for i, hop in enumerate(report.hop_metadata):
            if i == 0:
                dst = hop.switch_id
                continue
            else:
                queue_load = hop.queue_occupancy
                src = hop.switch_id

            src_node = self.switches[src-1]
            dst_node = self.switches[dst-1]
            current_path.insert(0, dst_node)
            
            self.G.edges[src_node, dst_node][dst_node+"weight"] = (queue_load/queue_size) / (self.G.node_to_node_interface_bw(src_node, dst_node) / self.max_bw)

            dst = src

        current_path.insert(0, src_node)
        current_path.insert(0, src_host)
        current_path.append(dst_host)

        key = hash_list(current_path[1:-1])
        if key not in self.path_infos:
            self.path_infos[key] = path_infos()
        self.path_infos[key].add_weight(self.weight_path(current_path), time.time())

        if report.update_path and report.ethertype == 0x86dd:
            
            p = self.select_path(src_host, dst_host, self.detour)
            # print("p1 = {}  w={} t={}".format(current_path, self.weight_path(current_path), report.trend))
            # print("p2 = {}  w={}".format(p, self.weight_path(p)))

            # print("trend {} max_qdepth {}".format(report.trend, report.max_qdepth))
            if self.weight_path(current_path) < self.weight_path(p)+self.delta:
                return

            # print(report.flow_id)
            
            # print(self.flows)

            

            # key = hash_list(current_path[1:-1])
            # if key in self.path_infos:
            #     l = self.path_infos[key].get_len()
            #     print([x for _, x in sorted(zip(self.path_infos[key].times[:l], self.path_infos[key].weights[:l]))])
            #     print(self.path_infos[key].linreg())

            # Avoid exporting several times the same path
            if(self.get_path_digest(report.flow_id.values()) != hash_list(p)):
                # self.count_flap(report.flow_id.values())
                res = self.path_to_ips(p)
                self.export_path(res, self.G.get_p4switch_id(p[1]), self.G.get_thrift_port(p[1]))
                self.store_flow_path(report.flow_id.values(), p)
            #print("update_infos : --- %s seconds ---" % (time.time() - start_time))

    def count_flap(self, flow_id):
        key = hash_list(flow_id)
        flaps[key] += 1


    def weight_path(self, p):
        src = p[0]
        w = 0
        for n in p[1:]:
            #print("nodes: {} {}".format(src, n))
            try:
                w += self.G.edges[src, n][n+"weight"]
            except Exception as e:
                pass
            src = n
        return w

    def compare_paths(self, p1, p2):
        return p1 if self.weight_path(p1) < self.weight_path(p2) else p2

    def select_path(self, src, dst, detour):
        #generator = nx.all_shortest_paths(self.G, source=src, target=dst)
        key = hash_list([src, dst])
        if key in self.paths:
            paths = self.paths[key]
        else:
            spl = nx.shortest_path_length(self.G, source=src, target=dst)
            generator = nx.all_simple_paths(self.G, source=src, target=dst, cutoff=spl+detour)#generate all paths with a detour of at most "detour" nodes more than the shortest path
            paths = list(generator)
            self.paths[key] = paths
        
        len_p = len(paths)

        # print(self.pathes)
        # print(paths)

        if len_p == 0:
            return None

        if len_p == 1:
            return paths[0]

        ids = random.sample(range(len_p), 2)
        p1 = paths[ids[0]]
        p2 = paths[ids[1]]

        return self.compare_paths(p1, p2)

    def path_to_ips(self, p):
        src = p[0]
        ips = []
        for n in p[1:]:
            if self.G.isHost(n):
                ips.append(converttov6(mac_to_v4(self.G.get_host_mac(n))))
            else:
                ips.append(mac_to_ipv6_linklocal(self.G.node_to_node_mac(n, src)))
                src = n
        return ips

    def export_path(self, p, id_s, port):
        p = p[1:]

        if not self.thrift_switches[id_s]:
            self.thrift_switches[id_s] = SimpleSwitchThriftAPI(port, "192.168.0.1")

        len_p = len(p)

        try:
            self.thrift_switches[id_s].table_modify_match('srv6_transit', 'srv6_t_insert_'+str(len_p), [(p[-1]+"/128")], p)
        except UIn_Error as e:
            self.thrift_switches[id_s].table_add('srv6_transit', 'srv6_t_insert_'+str(len_p), [(p[-1]+"/128")], p)
        


class HopMetadata:
    def __init__(self, data, ins_map, int_version=1):
        self.data = data
        self.ins_map = ins_map
        
        self.__parse_switch_id()
        self.__parse_ports()
        self.__parse_hop_latency()
        self.__parse_queue_occupancy()
        
        self.__parse_ingress_timestamp()
        self.__parse_egress_timestamp()
        if int_version == 0:
            self.__parse_queue_congestion()
        elif int_version >= 1:
            self.__parse_l2_ports()
        self.__parse_egress_port_tx_util()
        
    def __parse_switch_id(self):
        if self.ins_map & 0x80:
            self.switch_id = int.from_bytes(self.data.read(4), byteorder='big')
            logger.debug('parse switch id: %d' % self.switch_id)
        
    def __parse_ports(self):
        if self.ins_map & 0x40:
            self.l1_ingress_port_id = int.from_bytes(self.data.read(2), byteorder='big')
            self.l1_egress_port_id = int.from_bytes(self.data.read(2), byteorder='big')
            logger.debug('parse ingress port: %d, egress_port: %d' % (self.l1_ingress_port_id , self.l1_egress_port_id))
        
    def __parse_hop_latency(self):
        if self.ins_map & 0x20:
            self.hop_latency  = int.from_bytes(self.data.read(4), byteorder='big')
            logger.debug('parse hop latency: %d' %  self.hop_latency)

    def __parse_trend(self):
        LEADING_BIT_MASK =  0b100000000000000000000000
        VALUE_BIT_MASK =  0b011111111111111111111111

        self.trend = (self.queue_occupancy & LEADING_BIT_MASK) >> 23
        self.queue_occupancy = self.queue_occupancy & VALUE_BIT_MASK
    
    def __parse_queue_occupancy(self):
        if self.ins_map & 0x10:
            self.queue_occupancy_id = int.from_bytes(self.data.read(1), byteorder='big')
            self.queue_occupancy = int.from_bytes(self.data.read(3), byteorder='big')
            self.__parse_trend()
            logger.debug('parse queue_occupancy_id: %d, queue_occupancy: %d, trend: %d' % (self.queue_occupancy_id, self.queue_occupancy, self.trend))
            
    def __parse_ingress_timestamp(self):
        if self.ins_map & 0x08:
            self.ingress_timestamp  = int.from_bytes(self.data.read(8), byteorder='big')
            logger.debug('parse ingress_timestamp: %d' %  self.ingress_timestamp)
            
    def __parse_egress_timestamp(self):
        if self.ins_map & 0x04:
            self.egress_timestamp  = int.from_bytes(self.data.read(8), byteorder='big')
            logger.debug('parse egress_timestamp: %d' %  self.egress_timestamp)
            
    def  __parse_queue_congestion(self):
        if self.ins_map & 0x02:
            self.queue_congestion_id = int.from_bytes(self.data.read(1), byteorder='big')
            self.queue_congestion = int.from_bytes(self.data.read(3), byteorder='big')

            logger.debug('parse queue_congestion_id: %d, queue_congestion: %d' % (self.queue_congestion_id, self.queue_congestion))
            
    def  __parse_l2_ports(self):
        if self.ins_map & 0x02:
            self.l2_ingress_port_id = int.from_bytes(self.data.read(2), byteorder='big')
            self.l2_egress_port_id = int.from_bytes(self.data.read(2), byteorder='big')
            logger.debug('parse L2 ingress port: %d, egress_port: %d' % (self.l2_ingress_port_id , self.l2_egress_port_id))
            
    def  __parse_egress_port_tx_util(self):
        if self.ins_map & 0x01:
            self.egress_port_tx_util = int.from_bytes(self.data.read(4), byteorder='big')
            logger.debug('parse egress_port_tx_util: %d' % self.egress_port_tx_util)
            
    def unread_data(self):
        return self.data
            
    def __str__(self):
        attrs = vars(self)
        try:
            del attrs['data']
            del attrs['ins_map']
        except Exception as e: 
            logger.error(e)
        return pprint.pformat(attrs)



def ip2str(ip):
    return "{}.{}.{}.{}".format(ip[0],ip[1],ip[2],ip[3])



# ethernet(14B) + IP(20B) + UDP(8B)
UDP_OFFSET = 14 + 20 + 8
# ethernet(14B) + IP(20B) + TCP(20B)
TCP_OFFSET = 14 + 20 + 20



class IntReport():
    def __init__(self, data):
        orig_data = data
        #data = struct.unpack("!%dB" % len(data), data)
        '''
        header int_report_fixed_header_t {
            bit<4> ver;
            bit<4> len;
            bit<3> nprot;
            bit<6> rep_md_bits;
            bit<6> reserved;
            bit<1> d;
            bit<1> q;
            bit<1> f;
            bit<6> hw_id;
            bit<32> switch_id;
            bit<32> seq_num;
            bit<32> ingress_tstamp;
        }
        const bit<8> REPORT_FIXED_HEADER_LEN = 16;
        '''
        
        # report header
        self.int_report_hdr = data[:16]
        self.ver = self.int_report_hdr[0] >> 4
        
        if self.ver != 1:
            logger.error("Unsupported INT report version %s - skipping report" % self.int_version)
            raise Exception("Unsupported INT report version %s - skipping report" % self.int_version)
        
        self.len = self.int_report_hdr[0] & 0x0f
        self.nprot = self.int_report_hdr[1] >> 5
        self.rep_md_bits = (self.int_report_hdr[1] & 0x1f) + (self.int_report_hdr[2] >> 7)
        self.d = self.int_report_hdr[2] & 0x01
        self.q = self.int_report_hdr[3] >> 7
        self.f = (self.int_report_hdr[3] >> 6) & 0x01
        self.hw_id = self.int_report_hdr[3] & 0x3f
        self.switch_id, self.seq_num, self.ingress_tstamp = struct.unpack('!3I', orig_data[4:16])

        self.ethertype = int.from_bytes(data[28:30], byteorder='big')
        shift = 0
        if self.ethertype == 0x86dd:#IPV6 header
            shift = 20

        logger.info(self.ethertype)

        # flow id
        self.ip_hdr = data[30:50+shift]

        # logger.info(self.ip_hdr[6])
        # logger.info(str(IPv6Address(self.ip_hdr[8:24])))

        if self.ethertype == 0x86dd:
            if self.ip_hdr[6] == 43:#SRV6 header
                shift+= 8
                shift+= (int(data[74])+1)*16#add segments

        self.udp_hdr = data[50+shift:58+shift]

        # logger.info(struct.unpack('!H', self.udp_hdr[:2])[0])


        if self.ethertype == 0x86dd:#IPv6
            if self.ip_hdr[6] == 43:
                protocol = data[70]#SRV6H next header
                dst_ip = data[78:94]
            else :
                protocol = self.ip_hdr[6]
                dst_ip = self.ip_hdr[24:40]

            self.flow_id = {
                'srcip': str(IPv6Address(self.ip_hdr[8:24])),
                'dstip': str(IPv6Address(dst_ip)), 
                'scrp': struct.unpack('!H', self.udp_hdr[:2])[0],
                'dstp': struct.unpack('!H', self.udp_hdr[2:4])[0],
                'protocol': protocol,       
            }
        else :
            protocol = self.ip_hdr[9]
            self.flow_id = {
                'srcip': ip2str(self.ip_hdr[12:16]),
                'dstip': ip2str(self.ip_hdr[16:20]), 
                'scrp': struct.unpack('!H', self.udp_hdr[:2])[0],
                'dstp': struct.unpack('!H', self.udp_hdr[2:4])[0],
                'protocol': self.ip_hdr[9],       
            }

        # check next protocol
        # offset: udp/tcp + report header(16B)
        offset = 16 + shift
        if protocol == 17:
            offset = offset + UDP_OFFSET
        if protocol == 6:
            offset = offset + TCP_OFFSET

        self.update_path = data[offset]

        offset = offset + 1

        '''
        header intl4_shim_t {
            bit<8> int_type;
            bit<8> rsvd1;
            bit<8> len;   // the length of all INT headers in 4-byte words
            bit<6> rsvd2;  // dscp not put here
            bit<2> rsvd3;
        }
        const bit<16> INT_SHIM_HEADER_LEN_BYTES = 4;
        '''
        # int shim
        self.int_shim = data[offset:offset + 4]
        self.int_type = self.int_shim[0]
        self.int_data_len = int(self.int_shim[2]) - 3
        
        if self.int_type != 1: 
            logger.error("Unsupported INT type %s - skipping report" % self.int_type)
            raise Exception("Unsupported INT type %s - skipping report" % self.int_type)
  
        '''  INT header version 0.4     
        header int_header_t {
            bit<2> ver;
            bit<2> rep;
            bit<1> c;
            bit<1> e;
            bit<5> rsvd1;
            bit<5> ins_cnt;  // the number of instructions that are set in the instruction mask
            bit<8> max_hops; // maximum number of hops inserting INT metadata
            bit<8> total_hops; // number of hops that inserted INT metadata
            bit<16> instruction_mask;
            bit<16> rsvd2;
        }'''
        
        '''  INT header version 1.0
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
            bit<16>  instruction_mask;   
            bit<16> rsvd3;
        }'''


        # int header
        self.int_hdr = data[offset + 4:offset + 12]
        self.int_version = self.int_hdr[0] >> 4  # version in INT v0.4 has only 2 bits!
        if self.int_version == 0: # if rep is 0 then it is ok for INT v0.4
            self.hop_count = self.int_hdr[3]
        elif self.int_version == 1:
            self.hop_metadata_len = int(self.int_hdr[2] & 0x1f)
            self.remaining_hop_cnt = self.int_hdr[3]
            self.hop_count = int(self.int_data_len / self.hop_metadata_len)
            logger.debug("hop_metadata_len: %d, int_data_len: %d, remaining_hop_cnt: %d, hop_count: %d" % (
                            self.hop_metadata_len, self.int_data_len, self.remaining_hop_cnt, self.hop_count))
        else:
            logger.error("Unsupported INT version %s - skipping report" % self.int_version)
            raise Exception("Unsupported INT version %s - skipping report" % self.int_version)

        self.ins_map = int.from_bytes(self.int_hdr[4:6], byteorder='big')
        # first_slice = (self.ins_map & 0b0000111100000000) << 4
        # second_slice = (self.ins_map & 0b1111000000000000) >> 4
        # self.ins_map = (first_slice + second_slice) >> 8
        self.ins_map = self.ins_map >> 8
        
        logger.debug(hex(self.ins_map))

        # int metadata
        self.int_meta = data[offset + 12:]
        logger.debug("Metadata (%d bytes) is: %s" % (len(self.int_meta), binascii.hexlify(self.int_meta)))
        self.hop_metadata = []
        self.int_meta = io.BytesIO(self.int_meta)
        self.max_qdepth = 0
        self.trend = 0
        for i in range(self.hop_count):
            try:
                hop = HopMetadata(self.int_meta, self.ins_map, self.int_version)
                self.int_meta = hop.unread_data()
                # take the trend of most congested queue
                if self.max_qdepth < hop.queue_occupancy:
                    self.max_qdepth = hop.queue_occupancy
                    self.trend = hop.trend
                self.hop_metadata.append(hop)
            except Exception as e:
                logger.info("Metadata left (%s position) is: %s" % (self.int_meta.tell(), self.int_meta))
                logger.error(e)
                break

                
        logger.debug(vars(self))
            
    def __str__(self):
        hop_info = ''
        for hop in self.hop_metadata:
            hop_info += str(hop) + '\n'
        flow_tuple = "src_ip: %(srcip)s, dst_ip: %(dstip)s, src_port: %(scrp)s, dst_port: %(dstp)s, protocol: %(protocol)s" % self.flow_id 
        additional_info =  "sw: %s, seq: %s, int version: %s, ins_map: 0x%x, hops: %d" % (
            self.switch_id,
            self.seq_num,
            self.int_version,
            self.ins_map,
            self.hop_count,
        )
        return "\n".join([flow_tuple, additional_info, hop_info])
        


class IntCollector():
    
    def __init__(self, influx, period):
        self.influx = influx
        self.reports = []
        self.last_dstts = {} # save last `dstts` per each monitored flow
        self.last_reordering = {}  # save last `reordering` per each monitored flow
        self.last_hop_ingress_timestamp = {} #save last ingress timestamp per each hop in each monitored flow
        self.period = period # maximum time delay of int report sending to influx
        self.last_send = time.time() # last time when reports were send to influx
        
    def add_report(self, report):
        self.reports.append(report)
        
        reports_cnt = len(self.reports)
        logger.debug('%d reports ready to sent' % reports_cnt)
        # send if many report ready to send or some time passed from last sending
        if reports_cnt > 100 or time.time() - self.last_send > self.period:
            logger.info("Sending %d reports to influx from last %s secs" % (reports_cnt, time.time() - self.last_send))
            #self.__send_reports()
            self.last_send = time.time()
            
    def __prepare_e2e_report(self, report, flow_key):
        # e2e report contains information about end-to-end flow delay,         
        try:
            origin_timestamp = report.hop_metadata[-1].ingress_timestamp
            # egress_timestamp of sink node is creasy delayed - use ingress_timestamp instead
            destination_timestamp = report.hop_metadata[0].ingress_timestamp
        except Exception as e:
            origin_timestamp, destination_timestamp = 0, 0
            logger.error("ingress_timestamp in the INT hop is required, %s" % e)
        
        json_report = {
            "measurement": "int_telemetry",
            "tags": report.flow_id,
            'time': int(time.time()*1e9), # use local time because bmv2 clock is a little slower making time drift 
            "fields": {
                "origts": 1.0*origin_timestamp,
                "dstts": 1.0*destination_timestamp,
                "seq": 1.0*report.seq_num,
                "delay": 1.0*(destination_timestamp-origin_timestamp),
                }
        }
        
        # add sink_jitter only if can be calculated (not first packet in the flow)  
        if flow_key in self.last_dstts:
            json_report["fields"]["sink_jitter"] = 1.0*destination_timestamp - self.last_dstts[flow_key]
        
        # add reordering only if can be calculated (not first packet in the flow)  
        if flow_key in self.last_reordering:
            json_report["fields"]["reordering"] = 1.0*report.seq_num - self.last_reordering[flow_key] - 1
                        
        # save dstts for purpose of sink_jitter calculation
        self.last_dstts[flow_key] = destination_timestamp
        
        # save dstts for purpose of sink_jitter calculation
        self.last_reordering[flow_key] = report.seq_num
        return json_report
        
        #~ last_hop_delay = report.hop_metadata[-1].ingress_timestamp
        #~ for index, hop in enumerate(reversed(report.hop_metadata)):
            #~ if "hop_latency" in vars(hop):
                #~ json_report["fields"]["latency_%d" % index] = hop.hop_latency
            #~ if "ingress_timestamp" in vars(hop) and index > 0:
                #~ json_report["fields"]["hop_delay_%d" % index] = hop.ingress_timestamp - last_hop_delay
                #~ last_hop_delay = hop.ingress_timestamp
                
    def __prepare_hop_report(self, report, index, hop, flow_key):
        # each INT hop metadata are sent as independed json message to Influx
        tags = copy(report.flow_id)
        tags['hop_index'] = index
        json_report = {
            "measurement": "int_telemetry",
            "tags": tags,
            'time': int(time.time()*1e9), # use local time because bmv2 clock is a little slower making time drift 
            "fields": {}
        }
        
        # combine flow id with hop index 
        flow_hop_key = (*flow_key, index)
        
        # add sink_jitter only if can be calculated (not first packet in the flow)  
        if flow_hop_key in self.last_hop_ingress_timestamp:
            json_report["fields"]["hop_jitter"] =  hop.ingress_timestamp - self.last_hop_ingress_timestamp[flow_hop_key]
            
        if "hop_latency" in vars(hop):
            json_report["fields"]["hop_delay"] = hop.hop_latency
            
        if "ingress_timestamp" in vars(hop) and index > 0:
            json_report["fields"]["link_delay"] = hop.ingress_timestamp - self.last_hop_delay
            self.last_hop_delay = hop.ingress_timestamp
            
        if "ingress_timestamp" in vars(hop):
            # save hop.ingress_timestamp for purpose of node_jitter calculation
            self.last_hop_ingress_timestamp[flow_hop_key] = hop.ingress_timestamp
        return json_report
        
        
    def __prepare_reports(self, report):
        flow_key = "%(srcip)s, %(dstip)s, %(scrp)s, %(dstp)s, %(protocol)s" % report.flow_id 
        reports = []
        reports.append(self.__prepare_e2e_report(report, flow_key))
        
        self.last_hop_delay = report.hop_metadata[-1].ingress_timestamp
        for index, hop in enumerate(reversed(report.hop_metadata)):
            reports.append(self.__prepare_hop_report(report, index, hop, flow_key))
        return reports
        
        
    def __send_reports(self):
        json_body = []
        for report in self.reports:
            if report.hop_metadata:
                json_body.extend(self.__prepare_reports(report))
            else:
                logger.warning("Empty report metadata: %s" % str(report))
        logger.info("Json body for influx:\n %s" % pprint.pformat(json_body))
        if json_body:
            try:
                self.influx.write_points(json_body)
                self.last_send = time.time()
                logger.info(" %d int reports sent to the influx" % len(json_body))
            except Exception as e:
                logger.exception(e)
        self.reports = [] # clear reports sent

def unpack_int_report(packet):
    report = IntReport(packet)
    logger.info(report)
    return report
            

def influx_client(args):
    if ':' in args.host:
        host, port = args.host.split(':')
    else:
        host = args.host
        port = 8086
    user = 'admin'
    password = 'admin'
    dbname = args.database

    client = InfluxDBClient(host, port, user, password, 'int_telemetry_db')
    logger.info("Influx client ping response: %s" % client.ping())
    return client
    
    
def start_udp_server(args):
    bufferSize  = 65565
    port = args.int_port
    
    #influx = influx_client(args)
    influx = ""
    collector = IntCollector(influx, args.period)

    # Create a datagram socket
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, str("int_collector" + '\0').encode('utf-8'))
    sock.bind(("10.0.0.254", port))
    logger.info("UDP server up and listening at UDP port: %d" % port)

    g = NetGraph()
    # Listen for incoming datagrams
    while(True):
        message, address = sock.recvfrom(bufferSize)
        logger.info("Received INT report (%d bytes) from: %s" % (len(message), str(address)))
        logger.debug(binascii.hexlify(message))
        try:
            report = unpack_int_report(message)
            if report:
                g.update_infos(report)
                # collector.add_report(report)
        except Exception as e:
            logger.exception("Exception during handling the INT report")


def test_hopmetadata():
    ins_map = 0b11001100 << 8
    data = struct.pack("!I", 1)
    data += struct.pack("!HH", 2, 3)
    data += struct.pack("!Q", 11)
    data += struct.pack("!Q", 12)
    meta = HopMetadata(data, ins_map)
    print(meta)


if __name__ == "__main__":
    args = parse_params()
    if args.debug_mode > 0:
        logger.setLevel(logging.DEBUG)
    start_udp_server(args)

# SELECT mean("node_delay")  FROM int_telemetry  WHERE ("srcip" =~ /^$srcip$/ AND "dstip" =~ /^$dstip$/ AND  "node_index" =~ /^$hop$/) AND $timeFilter  GROUP BY time($interval) fill(null)
# SELECT mean("node_delay") FROM "int_udp_policy"."int_telemetry" WHERE ("srcip" = '10.0.1.1' AND "dstip" = '10.0.2.2' AND "hop_number" = '0') AND $timeFilter GROUP BY time($__interval) fill(null)