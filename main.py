"""
main.py
--------
CATES-PQC: Context-Aware Trust Evolution with Self-Adaptive Security for
Post-Quantum IoT Networks -- full research simulation.

Runs 100 rounds for each of the four compared approaches:
    1. No Security
    2. Always PQC Authentication
    3. Traditional Trust-Based Authentication (fixed threshold)
    4. Proposed CATES-PQC (context-aware dynamic weights + median/MAD
       adaptive thresholds + self-adaptive security + trust-aware routing)

Each round is driven as a SimPy timed event so the simulation follows an
event-based execution model as required by the framework, while remaining
lightweight enough to run on a normal laptop.

Outputs (written to results/):
    figure1_trust_evolution.png
    figure2_pdr_comparison.png
    figure3_energy_comparison.png
    figure4_latency_comparison.png
    figure5_detection_comparison.png
    figure6_lifetime_comparison.png
    figure6b_alive_fraction_over_time.png
    per_round_metrics.csv
    comparison_summary.csv
    comparison_table.txt
"""

import os
import numpy as np
import pandas as pd
import simpy

from network import IoTNetwork
from context_engine import ContextEngine
from trust_engine import DynamicWeightEngine, TrustEvolutionEngine, AdaptiveThresholdEngine
from authentication import SelfAdaptiveSecurityEngine, FIXED_TRUST_THRESHOLD
from routing import TrustAwareRouter
from metrics import MetricsCollector, confusion_metrics, build_comparison_table
import visualization as viz

# ----------------------------------------------------------------------
# Global simulation configuration
# ----------------------------------------------------------------------
NUM_NODES = 100
NUM_ROUNDS = 100
MALICIOUS_RATIO = 0.2
BASE_COMM_ENERGY = 0.15   # small per-round radio energy cost, independent of auth
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

METHOD_CONFIG = {
    "none": {
        "label": "No Security",
        "trust_aware_routing": False,
        "respect_quarantine": False,
        "use_dynamic_weights": False,
    },
    "always_pqc": {
        "label": "Always PQC",
        "trust_aware_routing": False,
        "respect_quarantine": False,
        "use_dynamic_weights": False,
    },
    "trust_fixed": {
        "label": "Traditional Trust-Based",
        "trust_aware_routing": False,
        "respect_quarantine": False,
        "use_dynamic_weights": False,
    },
    "cates_pqc": {
        "label": "CATES-PQC (Proposed)",
        "trust_aware_routing": True,
        "respect_quarantine": True,
        "use_dynamic_weights": True,
    },
}

FIXED_WEIGHTS = {"alpha": 0.25, "beta": 0.25, "gamma": 0.25, "delta": 0.25}


def run_method(method_key, seed=42, verbose=True):
    cfg = METHOD_CONFIG[method_key]
    label = cfg["label"]

    rng = np.random.default_rng(seed)
    network = IoTNetwork(num_nodes=NUM_NODES, malicious_ratio=MALICIOUS_RATIO, seed=seed)

    context_engine = ContextEngine(network)
    weight_engine = DynamicWeightEngine()
    trust_engine = TrustEvolutionEngine(lam=0.7)
    threshold_engine = AdaptiveThresholdEngine()
    security_engine = SelfAdaptiveSecurityEngine(method=method_key)
    router = TrustAwareRouter(network)

    collector = MetricsCollector(label)

    # Track a representative normal and malicious node for Figure 1
    normal_id = network.normal_ids()[0]
    malicious_id = network.malicious_ids()[0]
    trust_hist_normal, trust_hist_malicious = [], []

    recent_detection_rate = 0.0

    env = simpy.Environment()

    def simulation_process(env):
        nonlocal recent_detection_rate
        for round_num in range(1, NUM_ROUNDS + 1):
            yield env.timeout(1)  # advance the event clock by one round

            alive_ids = network.alive_nodes() if cfg["respect_quarantine"] else \
                [nid for nid, n in network.nodes.items() if n.alive]

            if len(alive_ids) < 2:
                # network exhausted -- record a flat continuation and stop early
                collector.record_round(round_num, 0, 0, 0.0, 0.0, 0, 0,
                                        recent_detection_rate, 0.0, 1.0,
                                        network.alive_fraction())
                trust_hist_normal.append(network.nodes[normal_id].trust_score)
                trust_hist_malicious.append(network.nodes[malicious_id].trust_score)
                continue

            # ---------------- 1. Generate communication ----------------
            # Only a fraction of nodes actively communicate each round --
            # authentication and radio energy cost apply only to these
            # participants, not to every idle alive node.
            num_pairs = max(1, int(len(alive_ids) * 0.20))
            senders = rng.choice(alive_ids, size=min(num_pairs, len(alive_ids)), replace=False)
            traffic_ratio = num_pairs / NUM_NODES

            pending_pairs = []
            for src in senders:
                candidates = [n for n in alive_ids if n != src]
                if not candidates:
                    continue
                dst = candidates[rng.integers(0, len(candidates))]
                pending_pairs.append((src, dst))
            participants = set()
            for src, dst in pending_pairs:
                participants.add(src)
                participants.add(dst)


            # ---------------- 2. Node behaviour feature extraction ------
            avg_consensus_estimate = 1.0 - (MALICIOUS_RATIO * 0.8)
            for nid in alive_ids:
                node = network.nodes[nid]
                neighbour_consensus = network.average_neighbour_trust(nid)
                node.generate_features(traffic_ratio, neighbour_consensus)

            # ---------------- 3. Update context --------------------------
            context = context_engine.update(round_num, traffic_ratio, recent_detection_rate)

            # ---------------- 4. Compute weights --------------------------
            weights = weight_engine.compute_weights(context) if cfg["use_dynamic_weights"] \
                else FIXED_WEIGHTS

            # ---------------- 5. Update trust ------------------------------
            for nid in alive_ids:
                trust_engine.update_trust(network.nodes[nid], weights)

            # ---------------- 6. Classify nodes (median/MAD) ---------------
            classification = threshold_engine.classify_all(network)
            labels = classification.get("labels", {})

            # Detection set depends on the method's own detection mechanism
            if method_key == "cates_pqc":
                # "Confirmed threat" tier: nodes the security engine actually
                # escalates to PQC or removes from routing. The broader
                # "Suspicious" band is monitored more closely but is not, by
                # itself, an accusation of malicious behaviour.
                flagged = [nid for nid, lab in labels.items()
                           if lab in ("Compromised", "Quarantined")]
            elif method_key == "trust_fixed":
                flagged = [nid for nid in alive_ids
                           if network.nodes[nid].trust_score < FIXED_TRUST_THRESHOLD]
            else:
                flagged = []  # no discrimination mechanism

            detection_rate, fpr, fnr = confusion_metrics(network, flagged)
            recent_detection_rate = detection_rate

            # ---------------- 7. Perform authentication --------------------
            # Only nodes actually communicating this round pay the
            # authentication cost (session establishment), not every idle
            # alive node in the network.
            round_latency = 0.0
            round_energy = 0.0
            lightweight_count = 0
            pqc_count = 0
            for nid in participants:
                node = network.nodes[nid]
                if not node.alive:
                    continue
                node.consume_energy(BASE_COMM_ENERGY)
                round_energy += BASE_COMM_ENERGY
                if not node.alive:
                    continue
                label = labels.get(nid)
                result = security_engine.authenticate(node, classification_label=label,
                                                       round_num=round_num)
                if result is not None:
                    round_latency += result["latency_ms"]
                    round_energy += result["energy"]
                    if result["mechanism"] == "lightweight":
                        lightweight_count += 1
                    elif result["mechanism"] == "pqc":
                        pqc_count += 1

            # ---------------- 8. Route packets ------------------------------
            sent, delivered = 0, 0
            still_alive = network.alive_nodes() if cfg["respect_quarantine"] else \
                [nid for nid, n in network.nodes.items() if n.alive]

            for src, dst in pending_pairs:
                if src not in still_alive or dst not in still_alive:
                    continue
                sent += 1

                found, path = router.find_path(
                    src, dst,
                    trust_aware=cfg["trust_aware_routing"],
                    respect_quarantine=cfg["respect_quarantine"],
                )
                if not found:
                    continue

                # simulate hop-by-hop packet delivery: only malicious
                # intermediate nodes meaningfully drop packets (packet
                # dropping / reduced forwarding attack behaviour). Normal
                # nodes forward reliably (small residual loss only).
                success = True
                for hop in path[1:-1]:
                    hop_node = network.nodes[hop]
                    if hop_node.is_malicious:
                        drop_prob = 1.0 - hop_node.features.get("pfr", 1.0)
                    else:
                        drop_prob = 0.02  # small baseline link loss
                    if rng.random() < drop_prob:
                        success = False
                        break
                if success:
                    delivered += 1


            # ---------------- 9. Collect metrics -----------------------------
            collector.record_round(
                round_num, sent, delivered, round_energy, round_latency,
                lightweight_count, pqc_count, detection_rate, fpr, fnr,
                network.alive_fraction(),
            )
            trust_hist_normal.append(network.nodes[normal_id].trust_score)
            trust_hist_malicious.append(network.nodes[malicious_id].trust_score)

    env.process(simulation_process(env))
    env.run(until=NUM_ROUNDS + 1)

    if verbose:
        print(f"  [done] {label}: {NUM_ROUNDS} rounds simulated.")

    return collector, trust_hist_normal, trust_hist_malicious


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("=" * 70)
    print("CATES-PQC Research Simulation")
    print("Context-Aware Trust Evolution with Self-Adaptive Security")
    print("for Post-Quantum IoT Networks")
    print("=" * 70)
    print(f"Nodes: {NUM_NODES} | Rounds: {NUM_ROUNDS} | Malicious ratio: {MALICIOUS_RATIO:.0%}\n")

    method_order = ["none", "always_pqc", "trust_fixed", "cates_pqc"]
    summaries = []
    method_dfs = {}
    all_round_dfs = []
    cates_trust_normal, cates_trust_malicious = None, None

    print("Running simulations for all four methods...")
    for key in method_order:
        collector, t_norm, t_mal = run_method(key, seed=42, verbose=True)
        summary = collector.summary()
        summaries.append(summary)
        df = collector.to_dataframe()
        method_dfs[METHOD_CONFIG[key]["label"]] = df
        all_round_dfs.append(df)
        if key == "cates_pqc":
            cates_trust_normal, cates_trust_malicious = t_norm, t_mal

    # ---------------- Save per-round CSV -----------------------------------
    combined_df = pd.concat(all_round_dfs, ignore_index=True)
    combined_csv_path = os.path.join(RESULTS_DIR, "per_round_metrics.csv")
    combined_df.to_csv(combined_csv_path, index=False)

    # ---------------- Build + save comparison table -------------------------
    summary_df = build_comparison_table(summaries)
    summary_csv_path = os.path.join(RESULTS_DIR, "comparison_summary.csv")
    summary_df.to_csv(summary_csv_path, index=False)

    table_txt_path = os.path.join(RESULTS_DIR, "comparison_table.txt")
    with open(table_txt_path, "w") as f:
        f.write(summary_df.to_string(index=False))

    print("\n" + "=" * 70)
    print("PERFORMANCE COMPARISON TABLE")
    print("=" * 70)
    pd.set_option("display.width", 160)
    pd.set_option("display.max_columns", 20)
    print(summary_df.to_string(index=False))

    # ---------------- Generate all figures -----------------------------------
    print("\nGenerating publication-quality figures (300 DPI PNG)...")
    viz.generate_all_figures(
        cates_trust_normal, cates_trust_malicious,
        summary_df, method_dfs, RESULTS_DIR,
    )

    print(f"\nAll results saved to: {RESULTS_DIR}")
    print("  - per_round_metrics.csv")
    print("  - comparison_summary.csv")
    print("  - comparison_table.txt")
    print("  - figure1_trust_evolution.png")
    print("  - figure2_pdr_comparison.png")
    print("  - figure3_energy_comparison.png")
    print("  - figure4_latency_comparison.png")
    print("  - figure5_detection_comparison.png")
    print("  - figure6_lifetime_comparison.png")
    print("  - figure6b_alive_fraction_over_time.png")
    print("\nSimulation complete.")


if __name__ == "__main__":
    main()
