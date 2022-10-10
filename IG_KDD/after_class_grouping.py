from math import log2
import pandas as pd


# Change the filenames to appropriate ones at two places before running.
# There are 3 non numeric attributes: "protocol_type", "service", and "flag".
# Information Gain for "src_bytes" attribute is the highest and "service" attribute comes second for all train and test datasets.
# Information Gain for "num_outbound_cmds" attribute was 0.0 because all the values were 0. Therefore, it was discarded.
# The results for Information gain are still similar after grouping the attack types.


# Grouping different attack types: (DoS, Probe, U2R, R2L)
# apache2 --> DoS
# back --> DoS
# buffer_overflow --> U2R
# ftp_write --> R2L
# guess_passwd --> R2L
# httptunnel --> R2L
# imap --> R2L
# ipsweep --> Probe
# land --> DoS
# loadmodule --> U2R
# mailbomb --> DoS
# multihop --> R2L
# mscan --> Probe
# named --> R2L
# neptune --> DoS
# nmap --> Probe
# perl --> U2R
# phf --> R2L
# pod --> DoS
# portsweep --> Probe
# processtable --> DoS
# ps --> U2R
# rootkit --> U2R
# saint --> Probe
# satan --> Probe
# sendmail --> R2L
# smurf --> DoS
# snmpgetattack --> R2L
# snmpguess --> R2L
# spy --> R2L
# sqlattack --> U2R
# teardrop --> DoS
# udpstorm --> DoS
# warezclient --> R2L
# warezmaster --> R2L
# worm --> DoS
# xlock --> R2L
# xsnoop --> R2L
# xterm --> U2R

DoS = [
    "apache2",
    "back",
    "land",
    "mailbomb",
    "neptune",
    "pod",
    "processtable",
    "smurf",
    "teardrop",
    "udpstorm",
    "worm",
]
Probe = ["ipsweep", "mscan", "nmap", "portsweep", "saint", "satan"]
U2R = ["buffer_overflow", "loadmodule", "perl", "ps", "rootkit", "sqlattack", "xterm"]
R2L = [
    "ftp_write",
    "guess_passwd",
    "httptunnel",
    "imap",
    "multihop",
    "named",
    "phf",
    "sendmail",
    "snmpgetattack",
    "snmpguess",
    "spy",
    "warezclient",
    "warezmaster",
    "xlock",
    "xsnoop",
]


attributes = []
with open("../NSL-KDD/KDDTest-21.arff", "r") as f:
    lines = f.readlines()
    for line in lines:
        if "@attribute" in line:
            attribute = line.split("'")[1]
            attributes.append(attribute)
attributes.append("unknown*")

df = pd.read_csv("../NSL-KDD/KDDTest-21.txt")
df.columns = attributes

for type in DoS:
    df["class"] = df["class"].replace(to_replace=type, value="DoS")
for type in Probe:
    df["class"] = df["class"].replace(to_replace=type, value="Probe")
for type in U2R:
    df["class"] = df["class"].replace(to_replace=type, value="U2R")
for type in R2L:
    df["class"] = df["class"].replace(to_replace=type, value="R2L")


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
