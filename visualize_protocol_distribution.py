import pandas as pd
import matplotlib.pyplot as plt

BEFORE = "data/exports_csv/all_packets.csv"
AFTER  = "data/exports_csv/all_packets_anonymized.csv"

print("[+] Loading files...")
df_before = pd.read_csv(BEFORE)
df_after  = pd.read_csv(AFTER)

# Ensure column exists
protocol_col = "_ws.col.protocol"

if protocol_col not in df_before.columns or protocol_col not in df_after.columns:
    raise Exception("Protocol column not found.")

# Count protocol frequencies
before_counts = df_before[protocol_col].value_counts()
after_counts  = df_after[protocol_col].value_counts()

# Combine into a single dataframe
protocol_compare = pd.concat([before_counts, after_counts], axis=1)
protocol_compare.columns = ["Before Privacy", "After Privacy"]
protocol_compare = protocol_compare.fillna(0)

# Plot
protocol_compare.plot(kind="bar", figsize=(10,6))
plt.title("Protocol Distribution Before vs After Privacy Mitigation")
plt.ylabel("Packet Count")
plt.xlabel("Protocol")
plt.grid(True)
plt.tight_layout()
plt.show()

print("✅ Protocol distribution visualization complete.")
