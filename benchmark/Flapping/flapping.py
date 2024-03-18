import pickle
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import numpy as np
import pickle
import matplotlib.pyplot as plt
from collections import Counter

# plt.rcParams["font.family"] = "Times New Roman"

# result = {}
# total_counts = 0

# for i in range(1, 11):
#     with open('benchmark/Flapping/flap' + str(i) + '.pkl', 'rb') as handle:
#         data = pickle.load(handle)
#     d = Counter(data.values())
#     result = {key: d.get(key, 0) + result.get(key, 0) for key in set(d) | set(result)}
#     total_counts += len(data)

# total_counts -= result[0]
# result.pop(0)


# percentage_result = {key: value / total_counts for key, value in result.items()}
# percentage_result_values = list(percentage_result.values())

# print(sum(percentage_result_values))

with open('smoothie.pkl', 'rb') as handle:
    percentage_result_values = pickle.load(handle)

with open('../Clove/benchmark/clove.pkl', 'rb') as handle:
    data = pickle.load(handle)

solution2_data = list(data.values())  # Solution 2 data

# 


aggregated_solution = solution2_data[:5] + [sum(solution2_data[5:])]

print(aggregated_solution)
print(sum(aggregated_solution))

x = np.arange(1, len(aggregated_solution) + 1)
while len(percentage_result_values) < len(aggregated_solution):
    percentage_result_values.append(0)

# plt.bar(x, aggregated_solution, width=0.4, label='Solution 1', color='blue')
# plt.bar(x, percentage_result_values, width=0.4, label='Solution 2', color='green')

# plt.xlabel('Number of Path Changes')
# plt.ylabel('Proportion')
# plt.title('Comparison of Path Changes between Solutions')
# plt.legend()

# plt.show()

# Create overlapping histograms
max_changes = 5
bin_labels = ["1 Rerouting"] + [str(i) + ' Reroutings' for i in range(2, max_changes + 1)] + [">5 Reroutings"]
x = range(len(bin_labels))

width = 0.35

fig, ax = plt.subplots(figsize=(12, 6))  # Adjust figure size
rects1 = ax.bar(x, percentage_result_values, width, label='Smoothie', color='blue')
rects2 = ax.bar([i + width for i in x], aggregated_solution, width, label='Clove', color='red')

ax.set_yscale('log')  # Set Y-axis to log scale
ax.set_xlabel('The Quantity of Flow Path Adjustments During the Flow\'s Lifetime', fontsize=20)
ax.set_ylabel('Percentage', fontsize=20, fontname="Times New Roman")
# ax.set_title('Flapping Comparison', fontsize=20, fontname="Times New Roman")
ax.set_xticks([i + width/2 for i in x])
ax.set_xticklabels(bin_labels, rotation=45, fontsize=15)  # Rotate x-axis labels for better readability
ax.legend(fontsize=15)

# Format y-axis labels as percentages
y_ticks = [0.001, 0.01, 0.1, 1]
y_tick_labels = ['0.1%', '1%', '10%', '100%']
ax.set_yticks(y_ticks)
ax.set_yticklabels(y_tick_labels, fontsize=15)

# Show the plot
plt.tight_layout()  # Adjust layout to prevent label cutoff
plt.grid()
plt.show()

