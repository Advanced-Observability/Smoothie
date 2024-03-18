#!/usr/bin/python

# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from scapy.all import Ether, IP, IPv6, sendp, get_if_hwaddr, get_if_list, TCP, Raw, UDP
import sys
import random, string
import time
from ipaddress import IPv6Address, IPv4Address
from p4utils.utils.helper import *

def is_ip_address(ip_string):
   try:
       ip_object = IPv4Address(ip_string)
       return True
   except ValueError:
       return False

def mac_to_v4(mac):
    mac_value = int(mac.translate({ord(' '): None, ord('.'): None, ord(':'): None, ord('-'): None}), 16)

    #port = mac_value >> 32 & 0xff
    high1 = mac_value >> 24 & 0xff
    high2 = mac_value >> 16 & 0xff
    low1 = mac_value >> 8 & 0xff
    low2 = mac_value & 0xff

    return '{}.{}.{}.{}'.format(high1, high2, low1, low2)

def converttov6(ipv4address):
    return IPv6Address('2002::' + ipv4address).compressed

def randomword(max_length):
    length = random.randint(1, max_length)
    return ''.join(random.choice(string.ascii_lowercase) for i in range(length))

def ip_from_topo(n_id):
    conf = load_conf("topology.json")
    nodes = conf.get("nodes")
    for x in nodes:
        #print(n_id)
        if x.get("id") == n_id:
            return x.get("ip").split('/')[0]


def send_random_traffic(dst, delay):
    start_time = time.process_time()
    dst_mac = None
    dst_ip = None
    src_inf = [i for i in get_if_list() if i.endswith('-eth0')]
    if len(src_inf) < 1:
        print ("No interface for output")
        sys.exit(1)
    src_mac = get_if_hwaddr(src_inf[0])
    src_ip = converttov6(mac_to_v4(src_mac))

    if not dst:
        conf = load_conf("topology.json")
        nodes = conf.get("nodes")
        n = random.choice(nodes)
        dst = n.get("ip").split('/')[0]

    if is_ip_address(dst):
        dst_ip = dst
    else:
        dst_ip = ip_from_topo(dst)
        if dst_ip == None:
            print ("Invalid host to send to")
            sys.exit(1)
    dst_mac = ip_address_to_mac(dst_ip) % (0)
    dst_ip = converttov6(dst_ip)

    pkt_cnt = 0
    total_pkts = 0
    last_sec = time.time()
    output_stream = sys.stdout
    random_ports = random.sample(range(1024, 65535), 1)
    for port in random_ports:
        # num_packets = random.randint(50, 250)
        num_packets = 1000
        for i in range(num_packets):
            # data = randomword(100)
            data = randomword(1)
            p = Ether(dst=dst_mac,src=src_mac)/IPv6(dst=dst_ip,src=src_ip)
            p = p/UDP(dport=port)/Raw(load=data)
            # p = p/TCP(dport=port)/Raw(load=data)
            #print (p.show())
            sendp(p, iface = src_inf[0], verbose=0)
            total_pkts += 1
            time.sleep(delay)
        
            pkt_cnt += 1
            if time.time()-last_sec > 1.0:
                output_stream.write("Pkt/s: {}\r".format(pkt_cnt))
                output_stream.flush()
                pkt_cnt = 0
                last_sec = time.time()
    print("%s" % (time.process_time() - start_time))
    print ("Sent %s packets in total" % total_pkts)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        send_random_traffic(None, 0)
    elif len(sys.argv) < 3:
        print("Usage: python sendV6.py dst_host_name delai")
        sys.exit(1)
    else:
        #print(ip_from_topo(sys.argv[1]))
        dst_name = sys.argv[1]
        delay = float(sys.argv[2])
        send_random_traffic(dst_name, delay)
