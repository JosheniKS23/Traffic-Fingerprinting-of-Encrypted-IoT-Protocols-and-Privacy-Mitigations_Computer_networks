import joblib
import pandas as pd
import numpy as np
import os

INPUT_FEATURES = "data/features_privacy/features_agg.csv"

print("[+] Searching for trained model...")

model_path = None
for root, dirs, files in os.walk("."):
    for file in files:
        if file.endswith(".joblib"):
            model_path = os.path.join(root, file)
            break

if model_path is None:
    raise FileNotFoundError("❌ No .joblib model found. Ask Person C for the trained model file.")

print(f"[✓] Found model: {model_path}")
model = joblib.load(model_path)

print("[+] Loading features for real-time prediction...")
df = pd.read_csv(INPUT_FEATURES)

# Remove label if present
if 'label' in df.columns:
    X = df.drop(columns=['label'])
else:
    X = df.copy()

# Predict
predictions = model.predict(X)
probabilities = model.predict_proba(X)

df["Predicted_Class"] = predictions
df["Confidence"] = np.max(probabilities, axis=1)

print("\n🔴 REAL-TIME CLASSIFICATION RESULTS 🔵")
print(df[["pcap_file_anon", "Predicted_Class", "Confidence"]])

print("\n[✓] Real-time classification complete.")
