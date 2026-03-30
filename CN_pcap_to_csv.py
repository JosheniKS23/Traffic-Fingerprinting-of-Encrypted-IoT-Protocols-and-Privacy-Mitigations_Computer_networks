#!/usr/bin/env python3
"""
CN_pcap_to_csv.py

Convert all PCAP files in input_dir to per-packet CSVs (one CSV per pcap) using tshark.
Also produces an aggregated `all_packets.csv` with an extra column `pcap_file`.

Usage:
    python CN_pcap_to_csv.py --pcap_dir captures/ --out_dir data/exports_csv --threads 1

Notes:
- Requires `tshark` in PATH for best performance. If not found it will try pyshark (slower).
- Exports the following fields (change TSHARK_FIELDS if you want more):
    frame_number, frame_time_epoch, ip_src, ip_dst, protocol, tcp_srcport, tcp_dstport,
    udp_srcport, udp_dstport, frame_len, tls_handshake_type, mqtt_topic
"""

import argparse
from pathlib import Path
import subprocess
import pandas as pd
import sys
import asyncio
from concurrent.futures import ThreadPoolExecutor


# --- Fix Windows asyncio issue for PyShark ---
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# --- Fields to export (tshark -e options) ---
TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "_ws.col.Protocol",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "tls.handshake.type",
    "mqtt.topic",
    "quic"
]


# --- Check if tshark is installed ---
def tshark_installed():
    try:
        subprocess.run(["tshark", "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True
    except Exception:
        return False


# --- Run tshark to export fields to CSV ---
def run_tshark_export(pcap_path: Path, out_csv: Path):
    cmd = ["tshark", "-r", str(pcap_path), "-T", "fields"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "header=y", "-E", "separator=,", "-E", "quote=d"]

    print(f"[+] Running tshark on {pcap_path} -> {out_csv}")
    with open(out_csv, "w", encoding="utf-8") as fout:
        proc = subprocess.run(cmd, stdout=fout, stderr=subprocess.PIPE, text=True)

    if proc.returncode != 0:
        print(f"[!] tshark returned code {proc.returncode} for {pcap_path}. stderr:\n{proc.stderr}", file=sys.stderr)
    return out_csv


# --- Fallback: use pyshark if tshark not found ---
def pyshark_export(pcap_path: Path, out_csv: Path):
    import pyshark
    print(f"[+] tshark not found — using pyshark fallback for {pcap_path}")
    cap = pyshark.FileCapture(str(pcap_path), include_raw=False, use_json=True)
    rows = []
    for pkt in cap:
        try:
            row = {
                "frame.number": getattr(pkt, "frame_info", {}).get("number", None) if hasattr(pkt, "frame_info") else None,
                "frame.time_epoch": getattr(pkt, "sniff_timestamp", None),
                "ip.src": pkt.ip.src if hasattr(pkt, "ip") else None,
                "ip.dst": pkt.ip.dst if hasattr(pkt, "ip") else None,
                "_ws.col.Protocol": pkt.highest_layer if hasattr(pkt, "highest_layer") else None,
                "tcp.srcport": pkt.tcp.srcport if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "srcport") else None,
                "tcp.dstport": pkt.tcp.dstport if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "dstport") else None,
                "udp.srcport": pkt.udp.srcport if hasattr(pkt, "udp") and hasattr(pkt.udp, "srcport") else None,
                "udp.dstport": pkt.udp.dstport if hasattr(pkt, "udp") and hasattr(pkt.udp, "dstport") else None,
                "frame.len": pkt.length if hasattr(pkt, "length") else None,
                "tls.handshake.type": None,
                "mqtt.topic": pkt.mqtt.topic if hasattr(pkt, "mqtt") and hasattr(pkt.mqtt, "topic") else None,
                "quic": None
            }
        except Exception:
            continue
        rows.append(row)
    cap.close()
    df = pd.DataFrame(rows)
    df.to_csv(out_csv, index=False)
    return out_csv


# --- Process a single PCAP ---
def process_pcap(pcap_path: Path, out_dir: Path, use_tshark: bool):
    out_dir.mkdir(parents=True, exist_ok=True)
    out_csv = out_dir / (pcap_path.stem + ".csv")
    if use_tshark:
        run_tshark_export(pcap_path, out_csv)
    else:
        pyshark_export(pcap_path, out_csv)

    # Add pcap filename column for traceability
    df = pd.read_csv(out_csv, dtype=str, keep_default_na=False)
    df.insert(0, "pcap_file", pcap_path.name)
    df.to_csv(out_csv, index=False)
    return out_csv


# --- Aggregate all CSVs into one ---
def aggregate_all(csv_paths, dest):
    dfs = []
    for p in csv_paths:
        df = pd.read_csv(p, dtype=str, keep_default_na=False)
        dfs.append(df)
    if dfs:
        big = pd.concat(dfs, ignore_index=True, sort=False)
        big.to_csv(dest, index=False)
        print(f"[+] Aggregated {len(dfs)} CSVs -> {dest} ({len(big)} rows)")
    else:
        print("[!] No CSVs to aggregate")


# --- Main Entry Point ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap_dir", required=True, help="Directory containing PCAP files")
    parser.add_argument("--out_dir", required=True, help="Directory to write CSVs")
    parser.add_argument("--threads", type=int, default=1, help="Parallel workers")
    args = parser.parse_args()

    pcap_dir = Path(args.pcap_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    use_tshark = tshark_installed()

    pcaps = sorted([p for p in pcap_dir.glob("*.pcap")])
    if not pcaps:
        print(f"[!] No pcaps found in {pcap_dir}")
        return

    csv_paths = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futures = [ex.submit(process_pcap, pcap, out_dir, use_tshark) for pcap in pcaps]
        for f in futures:
            csv_paths.append(f.result())

    aggregate_all(csv_paths, out_dir / "all_packets.csv")


if __name__ == "__main__":
    main()
