from math import log2
import pandas as pd
import threading


# Change the path and file to appropriate ones before running.
path = "../MachineLearningCVE/"


df = pd.read_csv(path + "columns_clustered_of_20_percent.csv")
# df = pd.read_csv(path + "20percent_of_combined.csv")

# Replacing all the values except BENIGN in the Label column to attack.
df["Label"] = df["Label"].replace(
    to_replace=r"^(?!BENIGN).*$", value="attack", regex=True
)


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

def calculate_information_gain(attribute):
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
        information_gain -= entropy_value * \
            (values_count[value] / total_data)
    information_gains[attribute] = information_gain

threads = []
print(df)
for attribute in df.columns:
    if attribute == "Label":
        continue
    thread = threading.Thread(target=calculate_information_gain, args=(attribute,))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()





# # Information Gain Calculation
# information_gains = {}
# for attribute in df.columns:
#     if attribute == "Label":
#         continue
#     else:
#         values = df[attribute].unique()
#         values_count = df[attribute].value_counts()
#         information_gain = entropy
#         for value in values:
#             entropy_value = 0
#             subdf = df.loc[df[attribute] == value, "Label"]
#             sclasses = subdf.unique()
#             sclasses_count = subdf.value_counts()
#             for sc in sclasses:
#                 entropy_sc = -(
#                     sclasses_count[sc]
#                     / values_count[value]
#                     * log2(sclasses_count[sc] / values_count[value])
#                 )
#                 entropy_value += entropy_sc
#             information_gain -= entropy_value * (values_count[value] / total_data)
#         information_gains[attribute] = information_gain

# Sorting attributes based on information gain values
sorted_information_gains = dict(
    sorted(information_gains.items(), key=lambda x: x[1], reverse=True)
)
for attribute, gain in sorted_information_gains.items():
    print("Information gain for", attribute, "::", gain)


# ----------------------- Obtained Result -----------------------
# Entropy of Dataset:: 0.7158799385480425
# Information gain for Total_Length_of_Fwd_Packets :: 0.4113990956809991
# Information gain for Subflow_Fwd_Bytes :: 0.4113990956809991
# Information gain for Init_Win_bytes_forward :: 0.3863868964640339
# Information gain for Max_Packet_Length :: 0.3771519251986193
# Information gain for Bwd_Packet_Length_Max :: 0.37615420554748336
# Information gain for Init_Win_bytes_backward :: 0.36010547097900136
# Information gain for Fwd_Packet_Length_Max :: 0.3551401565783331
# Information gain for Bwd_Header_Length :: 0.2542906223257398
# Information gain for Fwd_Header_Length :: 0.2484956083714557
# Information gain for Fwd_Header_Length.1 :: 0.2484956083714557
# Information gain for Total_Backward_Packets :: 0.18191671065047293
# Information gain for Subflow_Bwd_Packets :: 0.18191671065047293
# Information gain for Fwd_Packet_Length_Min :: 0.16666172091600426
# Information gain for Min_Packet_Length :: 0.1655741989346887
# Information gain for Bwd_Packet_Length_Min :: 0.15917061464793292
# Information gain for Total_Fwd_Packets :: 0.11765465871548421
# Information gain for Subflow_Fwd_Packets :: 0.11765465871548421
# Information gain for act_data_pkt_fwd :: 0.08137703946675072
# Information gain for min_seg_size_forward :: 0.061032539751982764
# Information gain for URG_Flag_Count :: 0.022564245250911323
# Information gain for PSH_Flag_Count :: 0.02131705484133123
# Information gain for FIN_Flag_Count :: 0.01977869607445766
# Information gain for Down/Up_Ratio :: 0.016998017633877656
# Information gain for ACK_Flag_Count :: 0.010929493650833566
# Information gain for Fwd_PSH_Flags :: 0.006214118151617765
# Information gain for SYN_Flag_Count :: 0.006214118151617765
# Information gain for ECE_Flag_Count :: 7.705150670211935e-05
# Information gain for RST_Flag_Count :: 7.67159684637031e-05
# Information gain for Fwd_URG_Flags :: 3.522413864409657e-05
# Information gain for CWE_Flag_Count :: 3.522413864409657e-05
