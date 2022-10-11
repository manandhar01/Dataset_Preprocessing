from math import log2
import pandas as pd
import numpy as np

# Change the path and file to appropriate ones before running.
path = "../MachineLearningCVE/"

df = pd.read_csv(path + "all_combined.csv")

# Replace np.inf and -np.inf with np.nan so that the corresponding rows can be dropped with df.dropna
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)


labels = df["Label"].unique()

# Extract x ramdom samples of each label from the dataset
x = 0.2
sdfs = []
for label in labels:
    subdf = df.loc[df["Label"] == label]
    sdf = subdf.sample(frac=x)
    sdfs.append(sdf)
df = pd.concat(sdfs)

df.to_csv(path+"20percent_of_combined.csv", index=False)
