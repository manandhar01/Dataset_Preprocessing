from math import log2
import pandas as pd


# Change the filenames to appropriate ones at two places before running.
# There are 3 non numeric attributes: "protocol_type", "service", and "flag".
# Information Gain for "src_bytes" attribute is the highest and "service" attribute comes second for all train and test datasets.
# Information Gain for "num_outbound_cmds" attribute was 0.0 because all the values were 0. Therefore, it was discarded.
# After binary grouping of attacks, the results are still similar to previous cases.

attributes = []
with open("../NSL-KDD/KDDTest+.arff", "r") as f:
    lines = f.readlines()
    for line in lines:
        if "@attribute" in line:
            attribute = line.split("'")[1]
            attributes.append(attribute)
attributes.append("unknown*")

df = pd.read_csv("../NSL-KDD/KDDTest+.txt")
df.columns = attributes

df["class"] = df["class"].replace(
    to_replace=r"^(?!normal).*$", value="attack", regex=True
)

# Every value in the 'duration' column is unique. So, dropping 'duration' column
df.drop("duration", axis=1, inplace=True)
attributes.remove("duration")

# Every value in the 'num_outbound_cmds' column is 0. So, dropping 'num_outbound_cmds' column
df.drop("num_outbound_cmds", axis=1, inplace=True)
attributes.remove("num_outbound_cmds")

# Entroppy Calculation
entropy = 0  # Entropy of the dataset
classes = df["class"].unique()
classes_count = df["class"].value_counts()
total_data = len(df)

for c in classes:
    entropy_c = -(classes_count[c] / total_data) * log2(classes_count[c] / total_data)
    entropy += entropy_c
print("Entropy of Dataset::", entropy)

# Information Gain Calculation
information_gains = {}
for attribute in attributes:
    if attribute == "class":
        continue
    else:
        values = df[attribute].unique()
        values_count = df[attribute].value_counts()
        information_gain = entropy
        for value in values:
            entropy_value = 0
            subdf = df.loc[df[attribute] == value, "class"]
            sclasses = subdf.unique()
            sclasses_count = subdf.value_counts()
            for sc in sclasses:
                entropy_sc = -(
                    sclasses_count[sc]
                    / values_count[value]
                    * log2(sclasses_count[sc] / values_count[value])
                )
                entropy_value += entropy_sc
            information_gain -= entropy_value * (values_count[value] / total_data)
        information_gains[attribute] = information_gain

# Sorting attributes based on information gain values
sorted_information_gains = dict(
    sorted(information_gains.items(), key=lambda x: x[1], reverse=True)
)
for attribute, gain in sorted_information_gains.items():
    print("Information gain for", attribute, "::", gain)
