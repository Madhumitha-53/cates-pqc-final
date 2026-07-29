"""
metrics.py
-----------
Module 9: Performance Evaluation Module.

Collects per-round and aggregate statistics for a single simulation run
(one of the four compared methods) and provides the confusion-matrix
style attack-detection metrics (detection rate / FPR / FNR).
"""

import numpy as np
import pandas as pd


class MetricsCollector:
    def __init__(self, method_name):
        self.method_name = method_name

        # Per-round rolling records (list of dicts) -> converted to DataFrame at the end
        self.round_records = []

        # Trust-history convenience (for Figure 1: trust evolution)
        self.trust_history_normal = []      # list of lists (per representative normal node)
        self.trust_history_malicious = []   # list of lists (per representative malicious node)

    # ------------------------------------------------------------------
    def record_round(self, round_num, sent, delivered, energy_used,
                      auth_latency_ms, lightweight_count, pqc_count,
                      detection_rate, fpr, fnr, alive_fraction):
        self.round_records.append({
            "round": round_num,
            "method": self.method_name,
            "packets_sent": sent,
            "packets_delivered": delivered,
            "pdr": (delivered / sent) if sent > 0 else 0.0,
            "energy_used": energy_used,
            "auth_latency_ms": auth_latency_ms,
            "lightweight_auth": lightweight_count,
            "pqc_auth": pqc_count,
            "detection_rate": detection_rate,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "alive_fraction": alive_fraction,
        })

    def to_dataframe(self):
        return pd.DataFrame(self.round_records)

    # ------------------------------------------------------------------
    def summary(self):
        df = self.to_dataframe()
        if df.empty:
            return {}

        # Network lifetime: first round alive_fraction drops below 0.5,
        # otherwise the full simulated horizon (all nodes survived).
        below_half = df[df["alive_fraction"] < 0.5]
        lifetime = int(below_half["round"].iloc[0]) if not below_half.empty else int(df["round"].max())

        return {
            "method": self.method_name,
            "avg_pdr": float(df["pdr"].mean()),
            "total_energy": float(df["energy_used"].sum()),
            "avg_energy_per_round": float(df["energy_used"].mean()),
            "avg_auth_latency_ms": float(df["auth_latency_ms"].mean()),
            "network_lifetime_rounds": lifetime,
            "avg_detection_rate": float(df["detection_rate"].mean()),
            "avg_false_positive_rate": float(df["false_positive_rate"].mean()),
            "avg_false_negative_rate": float(df["false_negative_rate"].mean()),
            "total_lightweight_auth": int(df["lightweight_auth"].sum()),
            "total_pqc_auth": int(df["pqc_auth"].sum()),
        }


def confusion_metrics(network, flagged_ids):
    """Given the set of node_ids flagged as malicious/suspicious this round,
    compute detection rate (recall), false positive rate, false negative
    rate against ground-truth malicious labels.
    """
    malicious = set(network.malicious_ids())
    normal = set(network.normal_ids())
    flagged = set(flagged_ids)

    tp = len(malicious & flagged)
    fn = len(malicious - flagged)
    fp = len(normal & flagged)
    tn = len(normal - flagged)

    detection_rate = tp / len(malicious) if malicious else 0.0
    fpr = fp / len(normal) if normal else 0.0
    fnr = fn / len(malicious) if malicious else 0.0

    return detection_rate, fpr, fnr


def build_comparison_table(summaries):
    """summaries: list of dicts (one per method) -> tidy DataFrame for the
    IEEE-style comparison table."""
    df = pd.DataFrame(summaries)
    rename = {
        "method": "Method",
        "avg_pdr": "Packet Delivery Ratio",
        "total_energy": "Total Energy Consumed",
        "avg_energy_per_round": "Avg Energy / Round",
        "avg_auth_latency_ms": "Avg Auth Latency (ms)",
        "network_lifetime_rounds": "Network Lifetime (rounds)",
        "avg_detection_rate": "Attack Detection Rate",
        "avg_false_positive_rate": "False Positive Rate",
        "avg_false_negative_rate": "False Negative Rate",
        "total_lightweight_auth": "Lightweight Auth Count",
        "total_pqc_auth": "PQC Auth Count",
    }
    df = df.rename(columns=rename)
    return df
