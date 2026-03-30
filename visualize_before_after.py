import pandas as pd
import matplotlib.pyplot as plt

# ==============================
# FILE PATHS
# ==============================
BEFORE_PATH = "data/features/features_agg.csv"
AFTER_PATH  = "data/features_privacy/features_agg.csv"

print(f"[+] Loading BEFORE features: {BEFORE_PATH}")
before = pd.read_csv(BEFORE_PATH)

print(f"[+] Loading AFTER features: {AFTER_PATH}")
after = pd.read_csv(AFTER_PATH)


# ==============================
# FEATURES TO COMPARE
# ==============================
features = [
    "mean_packet_size",
    "std_packet_size",
    "total_packets",
    "mean_iat"
]


# ==============================
# HISTOGRAM COMPARISON
# ==============================
for feature in features:
    if feature not in before.columns or feature not in after.columns:
        print(f"[!] Feature {feature} not found - skipping")
        continue

    plt.figure(figsize=(10, 6))

    plt.hist(
        before[feature],
        bins=10,
        alpha=0.5,
        label="Before Privacy",
        color="blue",
        edgecolor="black"
    )

    plt.hist(
        after[feature],
        bins=10,
        alpha=0.5,
        label="After Privacy",
        color="orange",
        edgecolor="black"
    )

    plt.title(f"Before vs After Privacy : {feature}")
    plt.xlabel(feature)
    plt.ylabel("Frequency")
    plt.legend()
    plt.grid(True)

    plt.show()


# ==============================
# BOXPLOT FOR PROTOCOL DIVERSITY
# ==============================
if "unique_protocols" in before.columns and "unique_protocols" in after.columns:
    plt.figure(figsize=(8, 5))

    plt.boxplot(
        [before["unique_protocols"], after["unique_protocols"]],
        labels=["Before Privacy", "After Privacy"]
    )

    plt.title("Protocol Diversity Before vs After Privacy")
    plt.ylabel("Unique Protocol Count")
    plt.grid(True)
    plt.show()


print("✅ Visualization complete.")
