#!/usr/bin/bash

task(){
   { python3 cool2.py $1 $2 ; } &>> ../benchmark/detour/$s\_$d.txt
}
for d in {0..5}
do
	s=16
	for i in {0..4}
	do
		for j in {1..5}
		do
			#python3 cool2.py $s $d &>> benchmark/$s\_$d.txt
			task $s $d &
			# echo -ne "detour: $d --- switches: $s --- test: $j\r"
		done
		s=$(($s*2))
	done
done

echo -ne "\n"