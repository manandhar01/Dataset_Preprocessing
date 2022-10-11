from math import log2
import pandas as pd

# Change the path and file to appropriate ones before running.
path = "../MachineLearningCVE/"
df = pd.read_csv(path + "20percent_of_combined.csv")

# # These attributes have only 0 value in all the rows. So, dropping them.
# df.drop(
#     [
#         "Bwd_PSH_Flags",
#         "Bwd_URG_Flags",
#         "Fwd_Avg_Bytes/Bulk",
#         "Fwd_Avg_Packets/Bulk",
#         "Fwd_Avg_Bulk_Rate",
#         "Bwd_Avg_Bytes/Bulk",
#         "Bwd_Avg_Packets/Bulk",
#         "Bwd_Avg_Bulk_Rate",
#     ],
#     axis=1,
#     inplace=True,
# )

# # There are too many attributes and calculating information gain for some of them takes forever
# # because there are a lot of different values in each of the rows. (mostly in the columns with data transfer rates)
# # Therefore this part of the code drops the attributes that have more than 50000 different values.
# # This is not the ideal way to do it.
# # We need to perform some sort of binning.
# # pd.set_option("display.max_rows", None)
# attributes_to_drop = []
# for attribute in df.columns:
#     if len(df[attribute].value_counts()) > 50000:
#         attributes_to_drop.append(attribute)
# df.drop(attributes_to_drop, axis=1, inplace=True)


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
# Entropy of Dataset:: 1.1083631186430698
# Information gain for Total_Length_of_Fwd_Packets :: 0.7024545627381815
# Information gain for Subflow_Fwd_Bytes :: 0.7024545627381815
# Information gain for Init_Win_bytes_forward :: 0.6972379333033323
# Information gain for Bwd_Packet_Length_Max :: 0.6561666935430637
# Information gain for Max_Packet_Length :: 0.6515666820424614
# Information gain for Init_Win_bytes_backward :: 0.6458275056641964
# Information gain for Fwd_Packet_Length_Max :: 0.6330314920356146
# Information gain for Fwd_Header_Length :: 0.5792633864378035
# Information gain for Fwd_Header_Length.1 :: 0.5792633864378035
# Information gain for Bwd_Header_Length :: 0.5484204369631649
# Information gain for Total_Backward_Packets :: 0.3885726101038441
# Information gain for Subflow_Bwd_Packets :: 0.3885726101038441
# Information gain for Total_Fwd_Packets :: 0.3534739331607344
# Information gain for Subflow_Fwd_Packets :: 0.3534739331607344
# Information gain for Bwd_Packet_Length_Min :: 0.324621436573904
# Information gain for min_seg_size_forward :: 0.28803773436833646
# Information gain for Min_Packet_Length :: 0.26040389644631884
# Information gain for Fwd_Packet_Length_Min :: 0.2575310190113791
# Information gain for act_data_pkt_fwd :: 0.2476248294995613
# Information gain for PSH_Flag_Count :: 0.13207981936074303
# Information gain for Down/Up_Ratio :: 0.0964517986327493
# Information gain for ACK_Flag_Count :: 0.07421974183955016
# Information gain for FIN_Flag_Count :: 0.04869910458883792
# Information gain for URG_Flag_Count :: 0.031352817737586164
# Information gain for Fwd_PSH_Flags :: 0.018783199829579544
# Information gain for SYN_Flag_Count :: 0.018783199829579544
# Information gain for ECE_Flag_Count :: 7.705150670211935e-05
# Information gain for RST_Flag_Count :: 7.671596846359208e-05
# Information gain for Fwd_URG_Flags :: 3.5224138643874525e-05
# Information gain for CWE_Flag_Count :: 3.5224138643874525e-05
