# 🚀 Traffic Fingerprinting of Encrypted IoT Protocols

## 📌 Overview

This project analyzes encrypted IoT traffic using statistical features and classifies traffic patterns while preserving privacy using anonymization techniques.

---
🎯 Objectives
Analyze encrypted IoT traffic without payload inspection
Extract statistical traffic patterns (fingerprints)
Classify traffic into behavioral categories
Apply privacy-preserving transformations
Compare performance before and after privacy mitigation

## ⚙️ Pipeline

PCAP → CSV → Feature Extraction → Privacy Mitigation → Classification → Visualization

---

## 📂 Files

* `CN_pcap_to_csv.py` – Convert PCAP to CSV
* `analyze_packets.py` – Basic analysis
* `feature_extract.py` – Feature generation
* `privacy_mitigation_and_features.py` – Privacy + features
* `realtime_classifier.py` – Prediction
* `visualize_*.py` – Graphs

---

## 🔧 Requirements

Python 3.8+
pandas
numpy
matplotlib
scikit-learn
joblib
tshark (recommended)

```bash
pip install pandas numpy matplotlib scikit-learn joblib
```

---

## 🚀 Run

```bash
python CN_pcap_to_csv.py --pcap_dir captures/ --out_dir data/exports_csv
python analyze_packets.py
python feature_extract.py
python privacy_mitigation_and_features.py
python visualize_before_after.py
python realtime_classifier.py
```

---

## 📊 Key Features

* Packet size statistics
* Inter-arrival time (IAT)
* Protocol counts (TCP, UDP, MQTT, TLS, QUIC)

---
🔐 Privacy Mitigation Techniques

To ensure user privacy, the following techniques are applied:

Hashing: IP addresses and MQTT topics anonymized using SHA256
Port Bucketing: Ports grouped into well-known, registered, dynamic
Timestamp Shifting: Randomized time offsets per PCAP
Identifier Removal: Original PCAP names replaced with hashes

👉 Goal: Preserve analytical utility while protecting sensitive data

---

## 🎯 Use Cases

* IoT traffic classification
* Network anomaly detection
* Privacy-preserving analytics

---

## ⚠️ Notes

* Install `tshark` for faster processing
* `.joblib` model required for prediction

---


