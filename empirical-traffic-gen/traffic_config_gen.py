from p4utils.utils.helper import load_topo
import sys
import pickle
from ipaddress import IPv6Address

def converttov6(ipv4address):
    return IPv6Address('2002::' + ipv4address).compressed

def gen_config(topo, distribution, load, nbr_requests, percentage):
	clients = []
	servers = []
	G = load_topo(topo)

	hosts = []
	for s in G.nodes():
		h = G.get_hosts_connected_to(s)
		if not h: continue
		hosts+=h

	for i, h in enumerate(hosts):
		if i%2==0: clients.append(h)
		else: servers.append(h)

	with open("/home/loic/empirical-traffic-gen/config/clients", "wb") as fp:
		pickle.dump(clients, fp)

	with open("/home/loic/empirical-traffic-gen/config/servers", "wb") as fp:
		pickle.dump(servers, fp)

	# print(clients)
	# print(servers)

	if load != 0:
		load=(float(load)*float(percentage))/100
	
	f = open("/home/loic/empirical-traffic-gen/config/config", "w")
	for s in servers:
		f.write("server "+converttov6(G.get_host_ip(s))+" 5050\n")
	f.write("req_size_dist "+distribution+ "\nfanout 1 100\nload "+str(load)+"Mbps\nnum_reqs "+nbr_requests)
	f.close()

if __name__ == "__main__":
	if len(sys.argv) != 6:
		print("5 args expected (path to topology.json, distribution, load in Mbps, nbr of requests, percentage of load)")
		exit(1)
	gen_config(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])