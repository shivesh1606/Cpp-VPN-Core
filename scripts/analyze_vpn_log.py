import re
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
import os
import numpy as np

LOG_FILE = os.path.abspath("../vpn.log")
OUT = Path("plots")
OUT.mkdir(exist_ok=True)


# Colors for clarity
C_TOTAL = "#2c3e50"    # Dark Blue
C_KERN  = "#e74c3c"    # Red (Kernel/Syscall)
C_CRYPTO = "#3498db"   # Blue (Crypto)
C_LOOKUP = "#f1c40f"   # Yellow (Logic)
C_OTHER  = "#95a5a6"   # Gray
# ---------- Parse ----------
records = []
current = {}

def flush():
    global current
    if current:
        records.append(current)
        current = {}

with open(LOG_FILE, encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()

        # ---- block boundary ----
        if "Stats (last" in line:
            flush()
            m = re.search(r"Stats \(last (\d+) sec\)", line)
            if m:
                current["interval_sec"] = int(m.group(1))

        # ---- traffic ----
        elif line.startswith("UDP RX:"):
            m = re.search(r"UDP RX: (\d+) pkts, (\d+) bytes, ([\d.]+) Mbps", line)
            if m:
                current["udp_rx_pkts"] = int(m.group(1))
                current["udp_rx_bytes"] = int(m.group(2))
                current["udp_rx_mbps"] = float(m.group(3))

        elif line.startswith("TUN TX:"):
            m = re.search(r"TUN TX: (\d+) pkts, (\d+) bytes, ([\d.]+) Mbps", line)
            if m:
                current["tun_tx_pkts"] = int(m.group(1))
                current["tun_tx_bytes"] = int(m.group(2))
                current["tun_tx_mbps"] = float(m.group(3))

        # ---- drops / backpressure ----
        elif "EAGAIN" in line:
            m = re.search(r"TUN read: (\d+), UDP recv: (\d+)", line)
            if m:
                current["tun_eagain"] = int(m.group(1))
                current["udp_eagain"] = int(m.group(2))

        elif line.startswith("UDP RX batches"):
            m = re.search(r"UDP RX batches: (\d+), avg pkts/batch: ([\d.]+)", line)
            if m:
                current["udp_rx_batches"] = int(m.group(1))
                current["avg_rx_batch"] = float(m.group(2))

        elif line.startswith("UDP TX batches"):
            m = re.search(r"UDP TX batches: (\d+), avg pkts/batch: ([\d.]+)", line)
            if m:
                current["udp_tx_batches"] = int(m.group(1))
                current["avg_tx_batch"] = float(m.group(2))

        # ---- crypto ----
        elif "Enc cycles/pkt" in line:
            m = re.search(
                r"Enc cycles/pkt: ([\d.]+), Dec cycles/pkt: ([\d.]+)", line
            )
            if m:
                current["enc_cyc_pkt"] = float(m.group(1))
                current["dec_cyc_pkt"] = float(m.group(2))

        # ---- userspace cost ----
        elif "Lookup cycles/pkt" in line:
            m = re.search(r"Lookup cycles/pkt: ([\d.]+), RX userspace cycles/pkt: ([\d.]+)", line)
            if m:
                current["lookup_cyc_pkt"] = float(m.group(1))
                current["rx_userspace_cyc_pkt"] = float(m.group(2))

        # ---- syscall + tun cost ----
        elif "RX syscall cycles/pkt" in line:
            m = re.search(
                r"RX syscall cycles/pkt: ([\d.]+), "
                r"TX syscall cycles/pkt: ([\d.]+), "
                r"TUN write cycles/pkt: ([\d.]+), "
                r"TUN read cycles/pkt: ([\d.]+)",
                line,
            )
            if m:
                current["rx_syscall_cyc_pkt"] = float(m.group(1))
                current["tx_syscall_cyc_pkt"] = float(m.group(2))
                current["tun_write_cyc_pkt"] = float(m.group(3))
                current["tun_read_cyc_pkt"] = float(m.group(4))
        elif line.startswith("Drops - "):
            m = re.search(r"TUN RX: (\d+), UDP TX: (\d+), UDP RX: (\d+)", line)
            if m:
                current["tun_rx_drops"] = int(m.group(1))
                current["udp_tx_drops"] = int(m.group(2))
                current["udp_rx_drops"] = int(m.group(3))

# flush last block
flush()

if not records:
    print("Error: No valid stat blocks found. Check if regex matches log format.")
    exit()

df = pd.DataFrame(records)
print("Parsed samples:", len(df))

# Convert everything numeric safely
df = df.apply(pd.to_numeric, errors="coerce")

# Drop incomplete samples
df = df.dropna()

# ---------- Derived Metrics ----------
safe_udp_pkts = df["udp_rx_pkts"].replace(0, np.nan)
safe_rx_total = df["rx_userspace_cyc_pkt"].replace(0, np.nan)

# Percentages strictly for the RX loop components
df["dec_pct"] = 100 * df["dec_cyc_pkt"] / safe_rx_total
df["lookup_pct"] = 100 * df["lookup_cyc_pkt"] / safe_rx_total
df["tun_write_pct"] = 100 * df["tun_write_cyc_pkt"] / safe_rx_total
df["other_pct"] = (100 - (df["dec_pct"] + df["lookup_pct"] + df["tun_write_pct"])).clip(lower=0)

# General metrics
df["pps"] = df["udp_rx_pkts"] / df["interval_sec"]
df["cycles_per_byte"] = df["rx_userspace_cyc_pkt"] / (df["udp_rx_bytes"] / safe_udp_pkts)
df["udp_eagain_rate"] = df["udp_eagain"] / df["interval_sec"]
df["tun_eagain_rate"] = df["tun_eagain"] / df["interval_sec"]

# Filter idle noise for all plots
df_plot = df[df["udp_rx_pkts"] > 1].copy()

# ---------- All Plots Restored & Fixed ----------

def save_clean_plot(dataframe, ycols, title, ylabel, fname):
    plt.figure(figsize=(10, 5))
    for col in ycols:
        plt.plot(dataframe[col].values, label=col, linewidth=1.5)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xlabel("Sample Index")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT / fname)
    plt.close()

# 1. Throughput (Restored)
save_clean_plot(df_plot, ["udp_rx_mbps", "tun_tx_mbps"], "Throughput", "Mbps", "throughput.png")

# 2. PPS (Restored)
save_clean_plot(df_plot, ["pps"], "Packets Per Second", "pps", "pps.png")

# 3. Batch Efficiency (Restored)
save_clean_plot(df_plot, ["avg_rx_batch", "avg_tx_batch"], "Batch Efficiency", "Pkts/Batch", "batch_efficiency.png")

# 4. Corrected RX Path Absolute
save_clean_plot(df_plot, ["rx_userspace_cyc_pkt", "tun_write_cyc_pkt", "dec_cyc_pkt"], 
                "RX Path cycles (UDP -> TUN)", "Cycles", "cpu_cycles_absolute.png")

# 5. Corrected RX Breakdown %
save_clean_plot(df_plot, ["tun_write_pct", "dec_pct", "lookup_pct", "other_pct"], 
                "RX Cost Breakdown (%)", "Percent", "cpu_breakdown_pct.png")

# 6. TX Path Overheads (New & Clear)
# Updated TX Path Plot
save_clean_plot(
    df_plot, 
    ["tx_syscall_cyc_pkt", "tun_read_cyc_pkt", "enc_cyc_pkt"], 
    "TX Path (TUN -> UDP) Overheads", 
    "Cycles", 
    "tx_path_costs.png"
)
# 7. Cycles per Byte (Restored)
save_clean_plot(df_plot, ["cycles_per_byte"], "Efficiency", "Cycles/Byte", "cycles_per_byte.png")

# 8. EAGAIN Rate (Restored)
save_clean_plot(df_plot, ["udp_eagain_rate", "tun_eagain_rate"], "EAGAIN Rate", "Events/Sec", "eagain_rate.png")
# 9. Packet Drops (New)
save_clean_plot(df_plot, ["tun_rx_drops", "udp_tx_drops", "udp_rx_drops"], 
                "Packet Drops Over Time", "Number of Packets", "drops.png")
print(f"Summary generated. All 8 plots saved to {OUT}/")