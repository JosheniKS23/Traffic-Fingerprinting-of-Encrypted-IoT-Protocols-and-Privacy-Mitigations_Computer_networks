#!/usr/bin/env python3
"""
analyze_packets.py

Quick analysis and visualization of all_packets.csv generated from PCAPs.
Shows:
- Protocol frequency
- Basic traffic stats
- Packet size histogram
"""

import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# === CONFIG ===
CSV_PATH = Path("data/exports_csv/all_packets.csv")

# === LOAD DATA ===
print(f"[+] Loading {CSV_PATH} ...")
df = pd.read_csv(CSV_PATH)

print("\n=== Basic Info ===")
print(df.info())
print("\n=== First 5 Rows ===")
print(df.head())

# Clean empty values
df = df.fillna("")

# === STATS ===
print("\n=== Summary Statistics ===")
if "frame.len" in df.columns:
    df["frame.len"] = pd.to_numeric(df["frame.len"], errors="coerce")
    print(df["frame.len"].describe())

# Protocol counts
if "_ws.col.Protocol" in df.columns:
    proto_counts = df["_ws.col.Protocol"].value_counts()
    print("\n=== Protocol Frequency ===")
    print(proto_counts)

    plt.figure(figsize=(8, 4))
    proto_counts.head(10).plot(kind="bar", color="steelblue")
    plt.title("Top Protocols")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.show()

# === Packet Size Histogram ===
if "frame.len" in df.columns:
    plt.figure(figsize=(8, 4))
    df["frame.len"].dropna().astype(float).plot(kind="hist", bins=40, color="lightcoral", edgecolor="black")
    plt.title("Packet Length Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.tight_layout()
    plt.show()

print("\n[+] Analysis complete.")
