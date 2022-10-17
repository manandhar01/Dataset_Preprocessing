import pandas as pd
from sklearn.cluster import KMeans

path = "../MachineLearningCVE/"
df = pd.read_csv(path + "20percent_of_combined.csv")

k = {
    "ACK_Flag_Count": 2,
    "Active_Max": 5,
    "Active_Mean": 4,
    "Active_Min": 4,
    "Active_Std": 5,
    "Average_Packet_Size": 4,
    "Avg_Bwd_Segment_Size": 3,
    "Avg_Fwd_Segment_Size": 3,
    "Bwd_Avg_Bulk_Rate": 1,
    "Bwd_Avg_Bytes/Bulk": 1,
    "Bwd_Avg_Packets/Bulk": 1,
    "Bwd_Header_Length": 2,
    "Bwd_IAT_Max": 3,
    "Bwd_IAT_Mean": 4,
    "Bwd_IAT_Min": 3,
    "Bwd_IAT_Std": 3,
    "Bwd_IAT_Total": 2,
    "Bwd_PSH_Flags": 1,
    "Bwd_Packet_Length_Max": 4,
    "Bwd_Packet_Length_Mean": 3,
    "Bwd_Packet_Length_Min": 4,
    "Bwd_Packet_Length_Std": 4,
    "Bwd_Packets/s": 3,
    "Bwd_URG_Flags": 1,
    "CWE_Flag_Count": 2,
    "Destination_Port": 2,
    "Down/Up_Ratio": 5,
    "ECE_Flag_Count": 2,
    "FIN_Flag_Count": 2,
    "Flow_Bytes/s": 5,
    "Flow_Duration": 3,
    "Flow_IAT_Max": 3,
    "Flow_IAT_Mean": 4,
    "Flow_IAT_Min": 4,
    "Flow_IAT_Std": 4,
    "Flow_Packets/s": 3,
    "Fwd_Avg_Bulk_Rate": 1,
    "Fwd_Avg_Bytes/Bulk": 1,
    "Fwd_Avg_Packets/Bulk": 1,
    "Fwd_Header_Length": 3,
    "Fwd_IAT_Max": 3,
    "Fwd_IAT_Mean": 4,
    "Fwd_IAT_Min": 4,
    "Fwd_IAT_Std": 3,
    "Fwd_IAT_Total": 3,
    "Fwd_PSH_Flags": 2,
    "Fwd_Packet_Length_Max": 5,
    "Fwd_Packet_Length_Mean": 4,
    "Fwd_Packet_Length_Min": 3,
    "Fwd_Packet_Length_Std": 5,
    "Fwd_Packets/s": 3,
    "Fwd_URG_Flags": 2,
    "Idle_Max": 3,
    "Idle_Mean": 3,
    "Idle_Min": 3,
    "Idle_Std": 4,
    "Init_Win_bytes_backward": 4,
    "Init_Win_bytes_forward": 4,
    "Max_Packet_Length": 5,
    "Min_Packet_Length": 5,
    "PSH_Flag_Count": 2,
    "Packet_Length_Mean": 4,
    "Packet_Length_Std": 4,
    "Packet_Length_Variance": 5,
    "RST_Flag_Count": 2,
    "SYN_Flag_Count": 2,
    "Subflow_Bwd_Bytes": 3,
    "Subflow_Bwd_Packets": 3,
    "Subflow_Fwd_Bytes": 5,
    "Subflow_Fwd_Packets": 3,
    "Total_Backward_Packets": 3,
    "Total_Fwd_Packets": 3,
    "Total_Length_of_Bwd_Packets": 3,
    "Total_Length_of_Fwd_Packets": 5,
    "URG_Flag_Count": 2,
    "act_data_pkt_fwd": 3,
    "min_seg_size_forward": 2,
}

columns_to_ignore = ["Destination_Port"]

columns = df.columns

for column in columns:
    if column == "Label":
        continue
    if column in columns_to_ignore:
        continue
    kmeans = KMeans(n_clusters=k[column])
    values = df[column].values.reshape(-1, 1)
    kmeans.fit(values)
    df[column] = kmeans.predict(values)

df.to_csv(path + "columns_clustered_of_20_percent.csv", index=False)
