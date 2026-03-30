#!/usr/bin/env python3
"""
privacy_mitigation_and_features.py

1) Read raw all_packets CSV (data/exports_csv/all_packets.csv)
2) Apply strong privacy mitigation:
   - Hash IPs (SHA256 truncated)
   - Hash MQTT topics
   - Bucket ports (well-known / registered / dynamic)
   - Per-PCAP timestamp random shift + ms rounding
   - Anonymize pcap filenames
3) Write anonymized packet CSV → data/exports_csv/all_packets_anonymized.csv
4) Recompute aggregated features → data/features_privacy/
   - features_agg.csv
   - train.csv / test.csv (if labels available)
"""

import os
import hashlib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

# ==========================================================
# CONFIG
# ==========================================================

INPUT_PATH = "data/exports_csv/all_packets.csv"
OUT_PACKET_CSV = "data/exports_csv/all_packets_anonymized.csv"
FEATURES_DIR = "data/features_privacy"

os.makedirs(os.path.dirname(OUT_PACKET_CSV), exist_ok=True)
os.makedirs(FEATURES_DIR, exist_ok=True)

HASH_LEN = 12  # truncate SHA256
TSHIFT_MIN = 60
TSHIFT_MAX = 600

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

# ==========================================================
# Helper functions
# ==========================================================

def sha256_trunc(s, length=HASH_LEN):
    if pd.isna(s) or s == "" or str(s).lower() == "nan":
        return ""
    st = str(s)
    return hashlib.sha256(st.encode("utf-8")).hexdigest()[:length]


def bucket_port(p):
    if pd.isna(p) or p == "" or str(p).lower() == "nan":
        return ""
    try:
        pv = int(float(p))
    except:
        return "other"
    if 0 <= pv <= 1023:
        return "well-known"
    if 1024 <= pv <= 49151:
        return "registered"
    if 49152 <= pv <= 65535:
        return "dynamic"
    return "other"


def anonymize_mqtt(topic):
    if pd.isna(topic) or topic == "" or str(topic).lower() == "nan":
        return ""
    return sha256_trunc(topic)


# ==========================================================
# Step 1: Load packets CSV
# ==========================================================

print(f"[+] Loading input CSV: {INPUT_PATH}")
df = pd.read_csv(INPUT_PATH, dtype=str)

df.columns = [c.strip() for c in df.columns]

if "frame.time_epoch" not in df.columns:
    raise RuntimeError("Expected column 'frame.time_epoch' not found.")

df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce")
if "frame.len" in df.columns:
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")

# ==========================================================
# Step 2: IP hashing
# ==========================================================

print("[+] Hashing IP addresses ...")
df["ip.src_anon"] = df["ip.src"].apply(sha256_trunc) if "ip.src" in df.columns else ""
df["ip.dst_anon"] = df["ip.dst"].apply(sha256_trunc) if "ip.dst" in df.columns else ""

df.drop(columns=[c for c in ["ip.src", "ip.dst"] if c in df.columns], inplace=True)

# ==========================================================
# Step 3: MQTT topic anonymization
# ==========================================================

if "mqtt.topic" in df.columns:
    print("[+] Hashing MQTT topics ...")
    df["mqtt.topic_anon"] = df["mqtt.topic"].apply(anonymize_mqtt)
    df.drop(columns=["mqtt.topic"], inplace=True)
else:
    df["mqtt.topic_anon"] = ""

# ==========================================================
# Step 4: Port bucketing
# ==========================================================

print("[+] Bucketing ports ...")
for col in ["tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]:
    if col in df.columns:
        df[col + "_bucket"] = df[col].apply(bucket_port)
        df.drop(columns=[col], inplace=True)
    else:
        df[col + "_bucket"] = ""

# ==========================================================
# Step 5: Timestamp shifting
# ==========================================================

print("[+] Applying per-PCAP timestamp shift ...")

if "pcap_file" not in df.columns:
    print("[!] No pcap_file column. Using global time shift.")
    shift_val = np.random.uniform(TSHIFT_MIN, TSHIFT_MAX)
    df["time_shifted"] = (df["frame.time_epoch"] + shift_val).round(3)
else:
    unique_pcaps = df["pcap_file"].unique()
    shift_map = {p: float(np.random.uniform(TSHIFT_MIN, TSHIFT_MAX)) for p in unique_pcaps}

    df["time_shifted"] = df.apply(
        lambda r: round(r["frame.time_epoch"] + shift_map.get(r["pcap_file"], 0.0), 3),
        axis=1
    )

df.drop(columns=["frame.time_epoch"], inplace=True)

# ==========================================================
# Step 6: Protocol + length cleanup
# ==========================================================

if "_ws.col.protocol" not in df.columns:
    df["_ws.col.protocol"] = ""
if "frame.len" not in df.columns:
    df["frame.len"] = np.nan

# ==========================================================
# Step 7: Anonymize pcap file names
# ==========================================================

print("[+] Hashing pcap filenames ...")

if "pcap_file" in df.columns:
    df["pcap_file_anon"] = df["pcap_file"].apply(sha256_trunc)
    df.drop(columns=["pcap_file"], inplace=True)
else:
    df["pcap_file_anon"] = ""

# ==========================================================
# Step 8: Write anonymized packets
# ==========================================================

print(f"[+] Writing anonymized packets CSV → {OUT_PACKET_CSV}")

cols_order = [
    "pcap_file_anon", "time_shifted", "frame.number", "frame.len",
    "ip.src_anon", "ip.dst_anon", "_ws.col.protocol",
    "tcp.srcport_bucket", "tcp.dstport_bucket",
    "udp.srcport_bucket", "udp.dstport_bucket",
    "tls.handshake.type", "quic", "mqtt.topic_anon"
]

existing = [c for c in cols_order if c in df.columns]
leftover = [c for c in df.columns if c not in existing]

df[existing + leftover].to_csv(OUT_PACKET_CSV, index=False)
print("[✓] Packet anonymization complete.")

# ==========================================================
# Step 9: Aggregate features
# ==========================================================

print("[+] Recomputing aggregated features ...")

df_agg = df.copy()
df_agg = df_agg.sort_values(["pcap_file_anon", "time_shifted"])

df_agg["iat"] = df_agg.groupby("pcap_file_anon")["time_shifted"].diff().fillna(0)

def extract_aggregates(g):
    return pd.Series({
        "total_packets": len(g),
        "mean_packet_size": g["frame.len"].mean(),
        "std_packet_size": g["frame.len"].std(),
        "min_packet_size": g["frame.len"].min(),
        "max_packet_size": g["frame.len"].max(),
        "median_packet_size": g["frame.len"].median(),
        "total_bytes": g["frame.len"].sum(),
        "mean_iat": g["iat"].mean(),
        "std_iat": g["iat"].std(),
        "tcp_pkts": (g["tcp.srcport_bucket"] != "").sum(),
        "udp_pkts": (g["udp.srcport_bucket"] != "").sum(),
        "mqtt_count": g["mqtt.topic_anon"].replace("", np.nan).dropna().shape[0],
        "unique_protocols": g["_ws.col.protocol"].nunique()
    })

# --- FutureWarning-free pandas groupby ---
features = (
    df_agg.groupby("pcap_file_anon", group_keys=False)
          .apply(lambda g: extract_aggregates(g), include_groups=False)
          .reset_index()
)
# ==========================================================
# Step 10: Label mapping from labels.csv
# ==========================================================

LABELS_XLSX = "data/logs/labels.csv.xlsx"

if os.path.exists(LABELS_XLSX):
    print(f"[+] Found Excel labels at {LABELS_XLSX}")

    labels_df = pd.read_excel(LABELS_XLSX, dtype=str)
    labels_df.columns = [c.strip() for c in labels_df.columns]

    if "pcap_file" in labels_df.columns and "label" in labels_df.columns:
        labels_df["pcap_file_anon"] = labels_df["pcap_file"].apply(sha256_trunc)
        label_map = dict(zip(labels_df["pcap_file_anon"], labels_df["label"]))
        features["label"] = features["pcap_file_anon"].map(label_map).fillna("unknown")
    else:
        print("[!] XLSX missing required columns: pcap_file, label")
        features["label"] = "unknown"

else:
    print("[!] labels.xlsx NOT found → all labels set to 'unknown'")
    features["label"] = "unknown"


# ==========================================================
# Save features
# ==========================================================

features_agg_path = os.path.join(FEATURES_DIR, "features_agg.csv")
features.to_csv(features_agg_path, index=False)
print(f"[✓] Saved features → {features_agg_path}")

# ==========================================================
# Step 11: Train/Test split
# ==========================================================

if features["label"].nunique() > 1 and "unknown" not in features["label"].unique():
    train_df, test_df = train_test_split(
        features, test_size=0.3, random_state=42, stratify=features["label"]
    )
    train_df.to_csv(os.path.join(FEATURES_DIR, "train.csv"), index=False)
    test_df.to_csv(os.path.join(FEATURES_DIR, "test.csv"), index=False)
    print("[✓] Train/test split created.")
else:
    print("[i] Train/test split skipped (insufficient labeled classes).")

print("[✓] Privacy mitigation + feature generation complete.")
