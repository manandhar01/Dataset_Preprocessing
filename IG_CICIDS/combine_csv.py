import pandas as pd
import os

path = '../MachineLearningCVE/'
csv_files = os.listdir(path)

dataframes = []
for file in csv_files:
    df = pd.read_csv(path+file)
    df.columns = df.columns.str.strip().str.replace(" ", "_")
    dataframes.append(df)
df = pd.concat(dataframes)

# Dropping redundant column "Fwd_Header_Length.1"
df.drop(["Fwd_Header_Length.1"], axis=1, inplace=True)

df.to_csv(path+"all_combined.csv", index=False)