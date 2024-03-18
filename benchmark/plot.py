import matplotlib.pyplot as plt
import os
import functools
import pandas as pd

def compare(s1, s2):
	s1 = s1.split('.')[0]
	s2 = s2.split('.')[0]

	s1 = s1.split('_')
	s2 = s2.split('_')

	if s1[0] == s2[0]:
		return int(s1[1]) - int(s2[1])
	else:
		return int(s1[0]) - int(s2[0])

def zero_to_nan(values):
    """Replace every 0 with 'nan' and return a copy."""
    return [float('nan') if x==0 else x for x in values]

metric = {}           

all_files = os.listdir("detour/")

all_files = sorted(all_files, key=functools.cmp_to_key(compare))

for fname in all_files:
	i=1
	f = open("detour/"+fname,'r')
	acc=0.0
	for row in f:
		try:
			acc += float(row)
		except Exception as e:
			continue
		i += 1
	acc /= i
	fname = fname.split('.')[0]
	info = fname.split('_')
	size = info[0]
	detour = info[1]
	try:
		metric[size].append(acc)
	except Exception as e:
		metric[size] = []
		metric[size].append(acc)
	

print(metric)


for x in metric.values():
	print(x)
	#plt.plot(range(0, 6), pd.Series(zero_to_nan(x)).interpolate(method='polynomial', order=2), '-o')
	plt.plot(range(0, 6), pd.Series(zero_to_nan(x)), '-o')
	plt.yscale("log")
# plt.bar(names, marks, color = 'g', label = 'File Data')
  
# plt.xlabel('Student Names', fontsize = 12)
# plt.ylabel('Marks', fontsize = 12)
  
# plt.title('Students Marks', fontsize = 20)
# plt.legend()
plt.show()