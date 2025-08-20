import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report
import joblib
import os
import matplotlib.pyplot as plt
import numpy as np
# Load dataset
df = pd.read_csv("Backend/ml/Phishing_Websites_Data.csv")

# Features and labels
X = df.drop(columns=["Result"])
y = df["Result"]

# Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = KMeans(n_clusters=2)
model.fit(X_train)

# Evaluate
y_pred = model.predict(X_train)
#print(classification_report(y_test, y_pred))

# Print clustering results
labels = model.labels_
clusterCount = np.bincount(labels)
print("Cluster counts:", clusterCount)

# Save model
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
model_path = os.path.join(BASE_DIR, "phishing_model.pkl")
joblib.dump(model, model_path)

print(f"✅ Model saved to: {model_path}")
