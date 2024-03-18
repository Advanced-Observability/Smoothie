#!/usr/bin/bash

task(){
	# Clean, generate topo, excecute 30 times
	bash clean.sh
	python Topos/TopoGenerator.py $1 $2
	{ python test.py --config Topos/test.json } &>> out.txt
	#{ python3 cool2.py $1 $2 ; } &>> ../benchmark/detour/$s\_$d.txt
}

for i in {0..4}
do
	s=6
	for p in {1..100..10}
	do
		for j in {1..20}
		do
			task $s $p
		done
		s=$(($s*2))
	done
done
