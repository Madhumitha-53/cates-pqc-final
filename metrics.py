"""
metrics.py
-----------
Module 9: Performance Evaluation Module.

Collects per-round and aggregate statistics for one simulation run, including
confusion-matrix attack-detection metrics (detection rate / FPR / FNR).
"""

import numpy as np
import pandas as pd


class MetricsCollector:
    HONEST_STATES = (
        "Excellent", "Trusted", "Suspicious", "Compromised", "Quarantined"
    )

    def __init__(self, method_name):
        self.method_name = method_name

        # Per-round rolling records (list of dicts) -> converted to DataFrame at the end
        self.round_records = []

        # Trust-history convenience (for Figure 1: trust evolution)
        self.trust_history_normal = []      # list of lists (per representative normal node)
        self.trust_history_malicious = []   # list of lists (per representative malicious node)
        self.threshold_history = []
        self.malicious_detection_rounds = {}
        self.malicious_node_count = 0

    def record_trust_means(self, nodes, alive_ids):
        """Record evaluation-only trust means grouped by ground-truth class."""
        for malicious, history in (
            (False, self.trust_history_normal),
            (True, self.trust_history_malicious),
        ):
            scores = [
                nodes[nid].trust_score for nid in alive_ids
                if nodes[nid].is_malicious == malicious
            ]
            history.append(float(np.mean(scores)) if scores else float("nan"))

    def record_thresholds(self, median, mad):
        self.threshold_history.append((median, mad))

    def record_detection(self, round_num, network, flagged_ids):
        """Record first-detection times; ground truth remains evaluation-only."""
        flagged = set(flagged_ids)
        malicious_ids = network.malicious_ids()
        self.malicious_node_count = len(malicious_ids)
        for nid in malicious_ids:
            if nid in flagged and nid not in self.malicious_detection_rounds:
                self.malicious_detection_rounds[nid] = round_num

    # ------------------------------------------------------------------
    def record_round(self, round_num, sent, delivered, energy_used,
                      auth_latency_ms, lightweight_count, pqc_count,
                      detection_rate, fpr, fnr, alive_fraction,
                      delivered_hops=0, network=None, scenario=None,
                      shift_round=50):
        record = {
            "round": round_num,
            "method": self.method_name,
            "packets_sent": sent,
            "packets_delivered": delivered,
            "pdr": (delivered / sent) if sent > 0 else 0.0,
            "throughput_packets_per_round": delivered,
            "delivered_hop_count_sum": delivered_hops,
            "avg_hop_count_delivered": (
                delivered_hops / delivered if delivered > 0 else np.nan
            ),
            "energy_used": energy_used,
            "auth_latency_ms": auth_latency_ms,
            "lightweight_auth": lightweight_count,
            "pqc_auth": pqc_count,
            "detection_rate": detection_rate,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "alive_fraction": alive_fraction,
        }
        if scenario == "shift":
            record["shift_phase"] = (
                "after" if round_num >= shift_round else "before"
            )
        if network is not None:
            alive_honest = [
                node for node in network.nodes.values()
                if node.alive and not node.is_malicious
            ]
            honest_count = len(alive_honest)
            for state in self.HONEST_STATES:
                record[f"honest_share_{state.lower()}"] = (
                    sum(node.security_class == state for node in alive_honest)
                    / honest_count if honest_count else np.nan
                )
        self.round_records.append(record)

    def to_dataframe(self):
        return pd.DataFrame(self.round_records)

    # ------------------------------------------------------------------
    def summary(self):
        df = self.to_dataframe()
        if df.empty:
            return {}

        # None means the experiment cap was reached before half the nodes died.
        below_half = df[df["alive_fraction"] < 0.5]
        lifetime = int(below_half["round"].iloc[0]) if not below_half.empty else None

        return {
            "method": self.method_name,
            "avg_pdr": float(df["pdr"].mean()),
            "total_energy": float(df["energy_used"].sum()),
            "avg_energy_per_round": float(df["energy_used"].mean()),
            "avg_auth_latency_ms": float(df["auth_latency_ms"].mean()),
            "network_lifetime_rounds": lifetime,
            "mean_time_to_detection_rounds": (
                float(np.mean(list(self.malicious_detection_rounds.values())))
                if self.malicious_detection_rounds else np.nan
            ),
            "malicious_nodes_detected": len(self.malicious_detection_rounds),
            "time_to_detection_coverage": (
                len(self.malicious_detection_rounds)
                / self.malicious_node_count if self.malicious_node_count else 0.0
            ),
            "avg_hop_count_delivered": (
                float(df["delivered_hop_count_sum"].sum()
                      / df["packets_delivered"].sum())
                if df["packets_delivered"].sum() else np.nan
            ),
            "throughput_packets_per_round": float(
                df["throughput_packets_per_round"].mean()
            ),
            "avg_detection_rate": float(df["detection_rate"].mean()),
            "avg_false_positive_rate": float(df["false_positive_rate"].mean()),
            "fpr_before_shift": (
                float(df.loc[df["shift_phase"] == "before",
                             "false_positive_rate"].mean())
                if "shift_phase" in df else np.nan
            ),
            "fpr_after_shift": (
                float(df.loc[df["shift_phase"] == "after",
                             "false_positive_rate"].mean())
                if "shift_phase" in df else np.nan
            ),
            "avg_false_negative_rate": float(df["false_negative_rate"].mean()),
            "total_lightweight_auth": int(df["lightweight_auth"].sum()),
            "total_pqc_auth": int(df["pqc_auth"].sum()),
            **{
                column: float(df[column].mean())
                for column in df.columns if column.startswith("honest_share_")
            },
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

    detection_rate = tp / len(malicious) if malicious else float("nan")
    fpr = fp / len(normal) if normal else 0.0
    fnr = fn / len(malicious) if malicious else float("nan")

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
