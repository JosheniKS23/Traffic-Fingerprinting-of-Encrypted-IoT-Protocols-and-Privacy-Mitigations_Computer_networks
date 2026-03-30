import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# === Paths ===
INPUT_CSV = "data/exports_csv/all_packets.csv"
OUT_DIR = "data/features"
os.makedirs(OUT_DIR, exist_ok=True)

print(f"[+] Loading {INPUT_CSV} ...")
df = pd.read_csv(INPUT_CSV)

# === Basic cleaning ===
df['pcap_file'] = df['pcap_file'].fillna('unknown')
df['frame.time_epoch'] = pd.to_numeric(df['frame.time_epoch'], errors='coerce')
df['frame.len'] = pd.to_numeric(df['frame.len'], errors='coerce')
df = df.dropna(subset=['frame.len', 'frame.time_epoch'])

# === Sort by time per pcap for IAT computation ===
df = df.sort_values(['pcap_file', 'frame.time_epoch'])

# === Compute inter-arrival times (IAT) per capture ===
df['iat'] = df.groupby('pcap_file')['frame.time_epoch'].diff().fillna(0)

# === Define a function to compute aggregate features ===
def extract_features(group):
    return pd.Series({
        'total_packets': len(group),
        'mean_packet_size': group['frame.len'].mean(),
        'std_packet_size': group['frame.len'].std(),
        'min_packet_size': group['frame.len'].min(),
        'max_packet_size': group['frame.len'].max(),
        'median_packet_size': group['frame.len'].median(),
        'total_bytes': group['frame.len'].sum(),
        'mean_iat': group['iat'].mean(),
        'std_iat': group['iat'].std(),
        'tcp_packets': group['_ws.col.protocol'].str.contains('TCP', na=False).sum(),
        'udp_packets': group['_ws.col.protocol'].str.contains('UDP', na=False).sum(),
        'mqtt_packets': group['_ws.col.protocol'].str.contains('MQTT', na=False).sum(),
        'tls_packets': group['_ws.col.protocol'].str.contains('TLS', na=False).sum(),
        'quic_packets': group['_ws.col.protocol'].str.contains('QUIC', na=False).sum(),
    })

print("[+] Extracting statistical features per capture ...")

features_df = df.groupby('pcap_file').apply(extract_features).reset_index()

# === Auto labeling based on filename ===
def auto_label(pcap):
    p = pcap.lower()
    if "attack" in p:
        return "attack"
    if "bursty" in p:
        return "bursty"
    if "periodic" in p:
        return "periodic"
    return "unknown"

features_df['label'] = features_df['pcap_file'].apply(auto_label)

# === Ensure labels contain no NaN ===
if features_df['label'].isna().any():
    print(features_df[['pcap_file', 'label']])
    raise Exception("ERROR: NaN labels exist — fix labeling before train/test split.")

# === Save aggregated features ===
agg_csv = os.path.join(OUT_DIR, "features_agg.csv")
features_df.to_csv(agg_csv, index=False)
print(f"[+] Saved aggregated features -> {agg_csv}")

# === Train/Test Split ===
train_df, test_df = train_test_split(
    features_df,
    test_size=0.3,
    random_state=42,
    stratify=features_df['label']
)

train_csv = os.path.join(OUT_DIR, "train.csv")
test_csv = os.path.join(OUT_DIR, "test.csv")

train_df.to_csv(train_csv, index=False)
test_df.to_csv(test_csv, index=False)

print(f"[+] Saved train/test splits -> {train_csv}, {test_csv}")
print("[✓] Feature extraction and dataset preparation complete.")
