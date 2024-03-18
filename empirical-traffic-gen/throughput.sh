cat $1./log/*.log | grep "Total RX Throughput:" | grep -oE '\-?[0-9]+|\-?[0-9]+\.[0-9]+' | datamash max 1 min 1 mean 1
