import pandas as pd
from sklearn.cluster import KMeans
import threading
import matplotlib.pyplot as plt

path = "../MachineLearningCVE/"
df = pd.read_csv(path + "20percent_of_combined.csv")

def get_plot(feature):
    sse = []
    epochs = range(1, 20)
    for k in epochs:
        kmeans = KMeans(n_clusters=k)
        values = df[feature].values.reshape(-1, 1)
        kmeans.fit(values)
        x = kmeans.predict(values)
        print(x)
        sse.append(kmeans.inertia_)
        plot_data.append({"epochs": epochs, "sse": sse, "feature": feature})



plot_data = []
plot_path = "Plots/"
if __name__ == "__main__":
    columns = df.columns
    t = []
    # a = 0
    for column in columns:
        if column == "Label":
            continue
        t1 = threading.Thread(target=get_plot, args=(column,))
        t1.start()
        t.append(t1)
        # if a == 1:
        #     break
        # a += 1

    for thread in t:
        thread.join()
    
    for data in plot_data:
        plt.clf()
        print(data)
        plt.xlabel("No. of clusters")
        plt.ylabel("SSE")
        plt.plot(data["epochs"], data["sse"])
        if "/" in data["feature"]:
            data["feature"] = data["feature"].replace("/", "_per")
        plt.savefig(plot_path + data["feature"])


