#!/usr/bin/bash

#sudo rm topology.json
sudo rm -rf log pcap
#sudo rm topos/*.txt topos/test.json
sudo rm -rf src/__pycache__
sudo rm p4_src/int.json p4_src/int.p4i

sudo mn -c
sudo pkill -f "python3 ./src/int_collector_influx.py"
ip a | grep -o "\([[:alnum:]]\+\_\)\?[[:alnum:]]\+\_[[:alnum:]]\+@[[:alnum:]]\+" | sed 's/\@.*$//' | while read line ; do sudo ip link delete "$line"; done


