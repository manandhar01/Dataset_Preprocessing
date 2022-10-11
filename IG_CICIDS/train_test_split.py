import pandas as pd

# Change the path and file to appropriate ones before running.
path = "../MachineLearningCVE/"

df = pd.read_csv(path + "20percent_of_combined.csv")

labels = df["Label"].unique()

# frac --> fraction of data to use for testing
frac = 0.3
sdfs = []
for label in labels:
    subdf = df.loc[df["Label"] == label]
    sdf = subdf.sample(frac=frac)
    sdfs.append(sdf)


test = pd.concat(sdfs)
train = df.drop(index=test.index)

test.to_csv(path+"30percent_test.csv", index=False)
train.to_csv(path+"70percent_train.csv", index=False)
