from math import log2
import pandas as pd

# Change the path and file to appropriate ones before running.
path = "../MachineLearningCVE/"

# Grouping different attack types: (DoS, Probe, U2R, R2L)
# Bot --> Bot
# DDoS --> DoS
# DoS GoldenEye --> DoS
# Dos Hulk --> DoS
# DoS Slowhttptest --> DoS
# DoS slowloris --> DoS
# FTP-Patator --> BruteForce
# Heartbleed --> DoS
# Infiltration --> Infiltration
# PortScan --> PortScan
# SSH-Patator --> BruteForce
# Web Attack � Brute Force --> WebAttack
# Web Attack � Sql Injection --> WebAttack
# Web Attack � XSS --> WebAttack


DoS = [
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS slowloris",
    "Heartbleed",
]
Bot = ["Bot"]
BruteForce = ["FTP-Patator", "SSH-Patator"]
Infiltration = ["Infiltration"]
PortScan = ["PortScan"]
WebAttack = [
    "Web Attack � Brute Force",
    "Web Attack � Sql Injection",
    "Web Attack � XSS",
]


df = pd.read_csv(path + "all_combined.csv")

for type in DoS:
    df["Label"] = df["Label"].replace(to_replace=type, value="DoS")
for type in Bot:
    df["Label"] = df["Label"].replace(to_replace=type, value="Bot")
for type in BruteForce:
    df["Label"] = df["Label"].replace(to_replace=type, value="Bruteforce")
for type in Infiltration:
    df["Label"] = df["Label"].replace(to_replace=type, value="Infiltration")
for type in PortScan:
    df["Label"] = df["Label"].replace(to_replace=type, value="PortScan")
for type in WebAttack:
    df["Label"] = df["Label"].replace(to_replace=type, value="WebAttack")


# These attributes have only 0 value in all the rows. So, dropping them.
df.drop(
    [
        "Bwd_PSH_Flags",
        "Bwd_URG_Flags",
        "Fwd_Avg_Bytes/Bulk",
        "Fwd_Avg_Packets/Bulk",
        "Fwd_Avg_Bulk_Rate",
        "Bwd_Avg_Bytes/Bulk",
        "Bwd_Avg_Packets/Bulk",
        "Bwd_Avg_Bulk_Rate",
    ],
    axis=1,
    inplace=True,
)


# There are too many attributes and calculating information gain for some of them takes forever
# because there are a lot of different values in each of the rows. (mostly in the columns with data transfer rates)
# Therefore this part of the code drops the attributes that have more than 50000 different values.
# This is not the ideal way to do it.
# We need to perform some sort of binning.
# pd.set_option("display.max_rows", None)
attributes_to_drop = []
for attribute in df.columns:
    if len(df[attribute].value_counts()) > 50000:
        attributes_to_drop.append(attribute)
df.drop(attributes_to_drop, axis=1, inplace=True)


# Entroppy Calculation
entropy = 0  # Entropy of the dataset
classes = df["Label"].unique()
classes_count = df["Label"].value_counts()
total_data = len(df)

for c in classes:
    entropy_c = -(classes_count[c] / total_data) * log2(classes_count[c] / total_data)
    entropy += entropy_c
print("Entropy of Dataset::", entropy)

# Information Gain Calculation
information_gains = {}
for attribute in df.columns:
    if attribute == "Label":
        continue
    else:
        values = df[attribute].unique()
        values_count = df[attribute].value_counts()
        information_gain = entropy
        for value in values:
            entropy_value = 0
            subdf = df.loc[df[attribute] == value, "Label"]
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




# ----------------------- Obtained Result -----------------------
# Entropy of Dataset:: 0.9296771562100459
# Information gain for Bwd_Packet_Length_Max :: 0.5583144507426427
# Information gain for Total_Length_of_Fwd_Packets :: 0.5545066739556286
# Information gain for Subflow_Fwd_Bytes :: 0.5545066739556286
# Information gain for Init_Win_bytes_backward :: 0.5524615315888104
# Information gain for Init_Win_bytes_forward :: 0.5426811976944242
# Information gain for Max_Packet_Length :: 0.5114059048122719
# Information gain for Fwd_Packet_Length_Max :: 0.49560854167462015
# Information gain for Bwd_Header_Length :: 0.44646493735176446
# Information gain for Fwd_Header_Length :: 0.4318448522179209
# Information gain for Fwd_Header_Length.1 :: 0.4318448522179209
# Information gain for Total_Backward_Packets :: 0.3532039038788099
# Information gain for Subflow_Bwd_Packets :: 0.3532039038788099
# Information gain for Bwd_Packet_Length_Min :: 0.3239784927424853
# Information gain for Total_Fwd_Packets :: 0.2902563847883176
# Information gain for Subflow_Fwd_Packets :: 0.2902563847883176
# Information gain for Fwd_Packet_Length_Min :: 0.23326986281407577
# Information gain for Min_Packet_Length :: 0.23092921987908555
# Information gain for min_seg_size_forward :: 0.2263750011012832
# Information gain for act_data_pkt_fwd :: 0.1849299213518572
# Information gain for PSH_Flag_Count :: 0.10624940898448493
# Information gain for Down/Up_Ratio :: 0.0881356308798337
# Information gain for ACK_Flag_Count :: 0.06991739938896102
# Information gain for FIN_Flag_Count :: 0.03205916372099611
# Information gain for URG_Flag_Count :: 0.028400910897352416
# Information gain for Fwd_PSH_Flags :: 0.012238687386660785
# Information gain for SYN_Flag_Count :: 0.012238687386660785
# Information gain for ECE_Flag_Count :: 7.705150670211935e-05
# Information gain for RST_Flag_Count :: 7.671596846381412e-05
# Information gain for Fwd_URG_Flags :: 3.522413864409657e-05
# Information gain for CWE_Flag_Count :: 3.522413864409657e-05
