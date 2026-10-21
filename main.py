"""Core CATES-PQC simulation and centralized, reproducible configuration."""

import json
import os

import numpy as np
import pandas as pd
import simpy

from authentication import (
    FIXED_TRUST_THRESHOLD,
    LIGHTWEIGHT_ENERGY,
    LIGHTWEIGHT_LATENCY_MS,
    PQC_ENERGY,
    PQC_LATENCY_MS,
    SESSION_LENGTH,
    SelfAdaptiveSecurityEngine,
)
from context_engine import ContextEngine
from metrics import MetricsCollector, confusion_metrics
from network import IoTNetwork
from routing import TrustAwareRouter
from trust_engine import (
    AdaptiveThresholdEngine,
    DynamicWeightEngine,
    FixedThresholdEngine,
    TrustEvolutionEngine,
)


CONFIG = {
    "NUM_NODES": 100,
    "NUM_ROUNDS": 100,
    "MALICIOUS_RATIO": 0.2,
    "radius": 0.18,
    "initial_energy_range": [50.0, 100.0],
    "sender_fraction": 0.20,
    "BASE_COMM_ENERGY": 0.15,
    "lambda": 0.7,
    "omega_formula_constants": {
        "pfr_weight": 0.4,
        "ci_weight": 0.4,
        "paid_weight": 0.2,
        "anomaly_threshold": 0.35,
        "scale": 0.15,
    },
    "weight_base_constants": {
        "alpha_base": 0.25, "alpha_scale": 0.5,
        "beta_base": 0.25, "beta_scale": 0.5,
        "gamma_base": 0.25, "gamma_scale": 0.5,
        "delta_base": 0.25, "delta_scale": 0.25,
    },
    "threshold_multipliers": {
        "upper": [2.0, 1.0],
        "lower": [1.0, 2.0],
    },
    "mad_floor": 1e-3,
    "abs_floor": 0.6,
    "distribution_shift": {
        "round": 50,
        "congestion_increase": 0.2,
        "honest_pfr_decrease": 0.12,
        "honest_paid_increase": 0.05,
        "honest_drop_probability_increase": 0.12,
    },
    "fixed_threshold_cutoffs": {
        "excellent": 0.8,
        "trusted": 0.65,
        "suspicious": 0.5,
        "compromised": 0.35,
    },
    "authentication_costs": {
        "lightweight_latency_ms": LIGHTWEIGHT_LATENCY_MS,
        "lightweight_energy": LIGHTWEIGHT_ENERGY,
        "pqc_latency_ms": PQC_LATENCY_MS,
        "pqc_energy": PQC_ENERGY,
        "fixed_trust_threshold": FIXED_TRUST_THRESHOLD,
    },
    "session_lengths": dict(SESSION_LENGTH),
    "attack_mode": "constant",
    "p_good": 0.5,
    "drop_probabilities": {
        "normal": 0.02,
        "malicious_range": [0.5, 0.9],
    },
    "behavioral_feature_ranges": {
        "normal_pfr": [0.8, 1.0],
        "normal_paid": [0.0, 0.15],
        "malicious_paid": [0.4, 1.0],
        "malicious_ci": [0.0, 0.5],
        "malicious_neighbour_degradation": [0.2, 0.5],
        "normal_neighbour_noise_std": 0.05,
        "congestion_noise_std": 0.03,
    },
    "threat_ema_alpha": 0.3,
    "experiment_settings": {
        "seeds": list(range(42, 62)),
        "malicious_ratios": [0.0, 0.1, 0.2, 0.3, 0.4],
        "attack_modes": ["constant", "on_off"],
        "lifetime_rounds": 400,
        "pqc_cost_multipliers": [3, 5, 10, 20],
        "lambda_values": [0.5, 0.7, 0.9],
        "threshold_k_values": [1.0, 1.5, 2.0],
        "mad_floors": [0.01, 0.03, 0.05, 0.10],
        "abs_floors": [None, 0.6],
        "shift_round": 50,
        "bootstrap_resamples": 10000,
    },
}

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
METHOD_CONFIG = {
    "none": {
        "label": "No Security", "auth_mode": "none",
        "trust_aware_routing": False, "respect_quarantine": False,
        "use_dynamic_weights": False, "session_lengths": CONFIG["session_lengths"],
    },
    "always_pqc": {
        "label": "Always PQC", "auth_mode": "always_pqc",
        "trust_aware_routing": False, "respect_quarantine": False,
        "use_dynamic_weights": False, "session_lengths": CONFIG["session_lengths"],
    },
    "trust_fixed": {
        "label": "Traditional Trust-Based", "auth_mode": "trust_fixed",
        "trust_aware_routing": False, "respect_quarantine": False,
        "use_dynamic_weights": False, "session_lengths": CONFIG["session_lengths"],
    },
    "cates_pqc": {
        "label": "CATES-PQC (Proposed)", "auth_mode": "cates_pqc",
        "trust_aware_routing": True, "respect_quarantine": True,
        "use_dynamic_weights": True, "session_lengths": CONFIG["session_lengths"],
        "mad_floor": 1e-3, "abs_floor": None,
    },
    "cates_pqc_guarded": {
        "label": "CATES-PQC (Guarded MAD)", "auth_mode": "cates_pqc",
        "trust_aware_routing": True, "respect_quarantine": True,
        "use_dynamic_weights": True, "session_lengths": CONFIG["session_lengths"],
        "mad_floor": 0.05, "abs_floor": 0.6,
    },
    "cates_no_routing": {
        "label": "CATES (No Routing/Quarantine)", "auth_mode": "cates_pqc",
        "trust_aware_routing": False, "respect_quarantine": False,
        "use_dynamic_weights": True, "session_lengths": CONFIG["session_lengths"],
    },
    "cates_no_cache": {
        "label": "CATES (No Cache)", "auth_mode": "cates_pqc",
        "trust_aware_routing": True, "respect_quarantine": True,
        "use_dynamic_weights": True,
        "session_lengths": {name: 0 for name in CONFIG["session_lengths"]},
    },
    "trust_fixed_cached": {
        "label": "Fixed Trust + Cache", "auth_mode": "trust_fixed_cached",
        "trust_aware_routing": False, "respect_quarantine": False,
        "use_dynamic_weights": False, "session_lengths": CONFIG["session_lengths"],
    },
    "trust_fixed_routing": {
        "label": "Fixed Trust + Routing", "auth_mode": "trust_fixed_routing",
        "trust_aware_routing": True, "respect_quarantine": False,
        "use_dynamic_weights": False, "session_lengths": CONFIG["session_lengths"],
    },
    "cates_fixed_weights": {
        "label": "CATES (Fixed Weights)", "auth_mode": "cates_pqc",
        "trust_aware_routing": True, "respect_quarantine": True,
        "use_dynamic_weights": False, "session_lengths": CONFIG["session_lengths"],
        "classifier": "adaptive",
    },
    "cates_fixed_threshold": {
        "label": "CATES (Fixed Thresholds)", "auth_mode": "cates_pqc",
        "trust_aware_routing": True, "respect_quarantine": True,
        "use_dynamic_weights": True, "session_lengths": CONFIG["session_lengths"],
        "classifier": "fixed",
    },
}
METHOD_ORDER = list(METHOD_CONFIG)
FIXED_WEIGHTS = {name: 0.25 for name in ("alpha", "beta", "gamma", "delta")}


def write_config(path=RESULTS_DIR, print_config=True):
    os.makedirs(path, exist_ok=True)
    saved = {"simulation": CONFIG, "methods": METHOD_CONFIG}
    with open(os.path.join(path, "config.json"), "w", encoding="utf-8") as stream:
        json.dump(saved, stream, indent=2)
        stream.write("\n")
    if print_config:
        print("Simulation configuration:")
        print(json.dumps(saved, indent=2))


def run_method(method_key, seed=42, verbose=True, num_rounds=None,
               malicious_ratio=None, attack_mode=None, overrides=None):
    """Run one method with the supplied common seed and scenario parameters."""
    cfg = METHOD_CONFIG[method_key]
    label = cfg["label"]
    rounds = CONFIG["NUM_ROUNDS"] if num_rounds is None else num_rounds
    ratio = CONFIG["MALICIOUS_RATIO"] if malicious_ratio is None else malicious_ratio
    mode = CONFIG["attack_mode"] if attack_mode is None else attack_mode
    overrides = overrides or {}
    scenario = overrides.get("scenario")
    lam = overrides.get("lambda", CONFIG["lambda"])
    auth_costs = {
        **CONFIG["authentication_costs"],
        **overrides.get("authentication_costs", {}),
    }
    threshold_multipliers = overrides.get(
        "threshold_multipliers", CONFIG["threshold_multipliers"]
    )
    mad_floor = overrides.get("mad_floor", cfg.get("mad_floor", CONFIG["mad_floor"]))
    abs_floor = overrides.get("abs_floor", cfg.get("abs_floor"))
    rng = np.random.default_rng(seed)
    network = IoTNetwork(
        num_nodes=CONFIG["NUM_NODES"],
        malicious_ratio=ratio,
        connect_radius=CONFIG["radius"],
        seed=seed,
        initial_energy_range=tuple(CONFIG["initial_energy_range"]),
        attack_mode=mode,
        p_good=CONFIG["p_good"],
        normal_drop_probability=CONFIG["drop_probabilities"]["normal"],
        behavior_config={
            **CONFIG["behavioral_feature_ranges"],
            "malicious_drop_range": CONFIG["drop_probabilities"]["malicious_range"],
        },
    )
    context_engine = ContextEngine(network, CONFIG["threat_ema_alpha"])
    weight_engine = DynamicWeightEngine(CONFIG["weight_base_constants"])
    trust_engine = TrustEvolutionEngine(
        lam, CONFIG["omega_formula_constants"]
    )
    if cfg.get("classifier") == "fixed":
        threshold_engine = FixedThresholdEngine(CONFIG["fixed_threshold_cutoffs"])
    else:
        threshold_engine = AdaptiveThresholdEngine(
            tuple(threshold_multipliers["upper"]),
            tuple(threshold_multipliers["lower"]),
            mad_floor=mad_floor,
            abs_floor=abs_floor,
        )
    security_engine = SelfAdaptiveSecurityEngine(
        method=cfg["auth_mode"],
        session_lengths=cfg["session_lengths"],
        respect_quarantine=cfg["respect_quarantine"],
        fixed_threshold=auth_costs["fixed_trust_threshold"],
        lightweight_latency_ms=auth_costs["lightweight_latency_ms"],
        lightweight_energy=auth_costs["lightweight_energy"],
        pqc_latency_ms=auth_costs["pqc_latency_ms"],
        pqc_energy=auth_costs["pqc_energy"],
    )
    router = TrustAwareRouter(network)
    collector = MetricsCollector(label)
    env = simpy.Environment()

    def record_trust_means(physical_alive_ids):
        collector.record_trust_means(network.nodes, physical_alive_ids)

    def simulation_process():
        for round_num in range(1, rounds + 1):
            yield env.timeout(1)
            physical_alive_ids = [
                nid for nid, node in network.nodes.items() if node.alive
            ]
            active_ids = network.alive_nodes() if cfg["respect_quarantine"] \
                else physical_alive_ids

            num_pairs = (
                max(1, int(len(active_ids) * CONFIG["sender_fraction"]))
                if len(active_ids) >= 2 else 0
            )
            senders = rng.choice(
                active_ids, size=min(num_pairs, len(active_ids)), replace=False
            ) if num_pairs else []
            traffic_ratio = num_pairs / CONFIG["NUM_NODES"]
            feature_traffic_ratio = traffic_ratio
            if (scenario == "shift"
                    and round_num >= CONFIG["distribution_shift"]["round"]):
                feature_traffic_ratio = min(
                    1.0, traffic_ratio
                    + CONFIG["distribution_shift"]["congestion_increase"]
                )
            pending_pairs = []
            for src in senders:
                candidates = [nid for nid in active_ids if nid != src]
                if candidates:
                    dst = candidates[rng.integers(0, len(candidates))]
                    pending_pairs.append((int(src), int(dst)))
            participants = {nid for pair in pending_pairs for nid in pair}

            # Trust state continues to evolve for physically alive quarantined nodes.
            neighbour_trusts = network.neighbour_trust_means()
            for nid in physical_alive_ids:
                node = network.nodes[nid]
                node.generate_features(
                    feature_traffic_ratio, neighbour_trusts[nid]
                )
                if (scenario == "shift"
                        and round_num >= CONFIG["distribution_shift"]["round"]):
                    shift = CONFIG["distribution_shift"]
                    if not node.is_malicious:
                        node.features["pfr"] = max(
                            0.0, node.features["pfr"] - shift["honest_pfr_decrease"]
                        )
                        node.features["paid"] = min(
                            1.0, node.features["paid"] + shift["honest_paid_increase"]
                        )
                        node.drop_probability = min(
                            1.0, node.normal_drop_probability
                            + shift["honest_drop_probability_increase"]
                        )
            context = context_engine.update(
                round_num, feature_traffic_ratio, neighbour_trusts
            )
            # This ablation disables trust-aware routing and quarantine, which
            # also changes active traffic and radio/auth energy. Its later
            # detection rates therefore are not a classification-only comparison.
            weights = weight_engine.compute_weights(context) \
                if cfg["use_dynamic_weights"] else FIXED_WEIGHTS
            for nid in physical_alive_ids:
                trust_engine.update_trust(network.nodes[nid], weights)

            classification = threshold_engine.classify_all(network)
            labels = classification.get("labels", {})
            collector.record_thresholds(
                classification.get("median", float("nan")),
                classification.get("mad", float("nan")),
            )
            if cfg["auth_mode"] == "cates_pqc":
                flagged = [
                    nid for nid, node_label in labels.items()
                    if node_label in ("Compromised", "Quarantined")
                ]
            elif cfg["auth_mode"].startswith("trust_fixed"):
                flagged = [
                    nid for nid in physical_alive_ids
                    if network.nodes[nid].trust_score < auth_costs["fixed_trust_threshold"]
                ]
            else:
                flagged = []
            detection_rate, fpr, fnr = confusion_metrics(network, flagged)
            collector.record_detection(round_num, network, flagged)

            round_latency = 0.0
            round_energy = 0.0
            lightweight_count = 0
            pqc_count = 0
            for nid in participants:
                node = network.nodes[nid]
                if not node.alive:
                    continue
                node.consume_energy(CONFIG["BASE_COMM_ENERGY"])
                round_energy += CONFIG["BASE_COMM_ENERGY"]
                if not node.alive:
                    continue
                result = security_engine.authenticate(
                    node, labels.get(nid), round_num
                )
                if result is not None:
                    round_latency += result["latency_ms"]
                    round_energy += result["energy"]
                    lightweight_count += result["mechanism"] == "lightweight"
                    pqc_count += result["mechanism"] == "pqc"

            sent, delivered, delivered_hops = 0, 0, 0
            routable_ids = network.alive_nodes() if cfg["respect_quarantine"] \
                else [nid for nid, node in network.nodes.items() if node.alive]
            router.prepare_round(
                trust_aware=cfg["trust_aware_routing"],
                respect_quarantine=cfg["respect_quarantine"],
            )
            for src, dst in pending_pairs:
                if src not in routable_ids or dst not in routable_ids:
                    continue
                sent += 1
                found, path = router.find_path(
                    src, dst,
                    trust_aware=cfg["trust_aware_routing"],
                    respect_quarantine=cfg["respect_quarantine"],
                )
                if not found:
                    continue
                success = all(
                    rng.random() >= network.nodes[hop].drop_probability
                    for hop in path[1:-1]
                )
                if success:
                    delivered += 1
                    delivered_hops += len(path) - 1

            collector.record_round(
                round_num, sent, delivered, round_energy, round_latency,
                lightweight_count, pqc_count, detection_rate, fpr, fnr,
                network.alive_fraction(), delivered_hops=delivered_hops,
                network=network, scenario=scenario,
                shift_round=CONFIG["distribution_shift"]["round"],
            )
            record_trust_means(set(physical_alive_ids))

    env.process(simulation_process())
    env.run(until=rounds + 1)
    if verbose:
        print(f"  [done] {label}: {rounds} rounds, seed={seed}, "
              f"ratio={ratio:.0%}, attack={mode}.")
    return collector, collector.trust_history_normal, collector.trust_history_malicious


def main():
    from experiments import main as run_experiments
    run_experiments()


if __name__ == "__main__":
    main()
