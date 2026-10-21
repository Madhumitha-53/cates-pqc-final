"""
trust_engine.py
----------------
Implements three tightly related modules from the CATES-PQC framework:

    Module 4: Dynamic Weight Engine
    Module 5: Adaptive Trust Evolution Engine
    Module 6: Adaptive Threshold Engine (Median + MAD)

The dynamic weight engine produces context-sensitive weights
    W = [alpha(congestion), beta(energy), gamma(threat), delta(neighbour)]
which are normalized to sum to 1 and used to combine behavioural features
into a single behaviour_score per node.

Trust evolution follows:
    TS(t+1) = lambda * TS(t) + (1 - lambda) * behaviour_score - Omega

where Omega is a malicious-behaviour penalty (zero for well-behaved nodes,
positive and growing for nodes exhibiting attack-like behaviour).

The adaptive threshold engine classifies every node every round using the
median (M) and median absolute deviation (MAD) of the trust-score
distribution, avoiding a fixed/hand-tuned cutoff.
"""

import numpy as np


class DynamicWeightEngine:
    """Module 4: produces normalized context-aware weights W."""

    def __init__(self, constants=None):
        self.constants = constants or {
            "alpha_base": 0.25, "alpha_scale": 0.5,
            "beta_base": 0.25, "beta_scale": 0.5,
            "gamma_base": 0.25, "gamma_scale": 0.5,
            "delta_base": 0.25, "delta_scale": 0.25,
        }

    def compute_weights(self, context):
        congestion = context["congestion"]
        energy_availability = context["energy_availability"]
        threat_level = context["threat_level"]
        neighbour_behaviour = context["neighbour_behaviour"]

        # Base weights (prior) -- kept modest so context can meaningfully
        # shift emphasis rather than dominate from a fixed baseline.
        c = self.constants
        alpha = c["alpha_base"] + c["alpha_scale"] * congestion
        beta = c["beta_base"] + c["beta_scale"] * (1.0 - energy_availability)
        gamma = c["gamma_base"] + c["gamma_scale"] * threat_level
        delta = c["delta_base"] + c["delta_scale"] * (1.0 - neighbour_behaviour)

        total = alpha + beta + gamma + delta
        w = np.array([alpha, beta, gamma, delta]) / total
        return {
            "alpha": float(w[0]), "beta": float(w[1]),
            "gamma": float(w[2]), "delta": float(w[3]),
        }


class TrustEvolutionEngine:
    """Module 5: adaptive trust evolution."""

    def __init__(self, lam=0.7, omega_constants=None):
        self.lam = lam
        self.omega_constants = omega_constants or {
            "pfr_weight": 0.4, "ci_weight": 0.4, "paid_weight": 0.2,
            "anomaly_threshold": 0.35, "scale": 0.15,
        }

    def behaviour_score(self, features, weights):
        """Combine PFR, (1-PAID) as delay proxy, CI, NC using dynamic weights.

        forwarding rate  -> weighted by alpha (congestion-driven)
        energy proxy (RE)-> weighted by beta  (energy-driven); included via
                            residual energy since low-energy nodes should be
                            treated more cautiously
        crypto integrity -> weighted by gamma (threat-driven)
        neighbour consensus -> weighted by delta
        """
        pfr = features["pfr"]
        delay_score = 1.0 - features["paid"]   # lower deviation -> higher score
        ci = features["ci"]
        re = features["re"]
        nc = features["nc"]

        alpha, beta, gamma, delta = (weights["alpha"], weights["beta"],
                                      weights["gamma"], weights["delta"])

        # forwarding + delay jointly represent "communication behaviour"
        comm_behaviour = 0.5 * pfr + 0.5 * delay_score

        score = (alpha * comm_behaviour + beta * re +
                 gamma * ci + delta * nc)
        return float(max(0.0, min(1.0, score)))

    def malicious_penalty(self, features):
        """Omega: penalty that grows with clearly malicious indicators
        (low forwarding, low crypto integrity, high jitter)."""
        pfr = features["pfr"]
        ci = features["ci"]
        paid = features["paid"]

        c = self.omega_constants
        anomaly = ((1.0 - pfr) * c["pfr_weight"]
                   + (1.0 - ci) * c["ci_weight"]
                   + paid * c["paid_weight"])
        # Only penalize meaningfully anomalous behaviour (soft threshold)
        omega = c["scale"] * max(0.0, anomaly - c["anomaly_threshold"])
        return float(omega)

    def update_trust(self, node, weights):
        behaviour = self.behaviour_score(node.features, weights)
        omega = self.malicious_penalty(node.features)
        new_trust = self.lam * node.trust_score + (1 - self.lam) * behaviour - omega
        node.record_trust(new_trust)
        return node.trust_score


class AdaptiveThresholdEngine:
    """Module 6: Median / MAD based dynamic classification."""

    LABELS = ["Quarantined", "Compromised", "Suspicious", "Trusted", "Excellent"]

    def __init__(self, upper_multipliers=(2.0, 1.0), lower_multipliers=(1.0, 2.0),
                 mad_floor: float = 1e-3, abs_floor: float | None = 0.6):
        self.upper_multipliers = upper_multipliers
        self.lower_multipliers = lower_multipliers
        self.mad_floor = mad_floor
        self.abs_floor = abs_floor

    def classify_all(self, network):
        alive_ids = [nid for nid, n in network.nodes.items() if n.alive]
        if not alive_ids:
            return {}

        trust_values = np.array([network.nodes[n].trust_score for n in alive_ids])
        M = float(np.median(trust_values))
        MAD = float(np.median(np.abs(trust_values - M)))
        # Guard against a degenerate (near-zero) MAD early in the simulation
        MAD = max(MAD, self.mad_floor)

        classifications = {}
        for nid in alive_ids:
            ts = network.nodes[nid].trust_score
            if ts > M + self.upper_multipliers[0] * MAD:
                label = "Excellent"
            elif ts > M + self.upper_multipliers[1] * MAD:
                label = "Trusted"
            elif ts > M - self.lower_multipliers[0] * MAD:
                label = "Suspicious"
            elif ts > M - self.lower_multipliers[1] * MAD:
                label = "Compromised"
            else:
                label = "Quarantined"
            if (self.abs_floor is not None and ts >= self.abs_floor
                    and label in ("Compromised", "Quarantined")):
                label = "Suspicious"
            network.nodes[nid].record_classification(label)
            classifications[nid] = label

        return {"labels": classifications, "median": M, "mad": MAD}


class FixedThresholdEngine:
    """Ablation classifier with explicit, non-adaptive trust cutoffs."""

    def __init__(self, cutoffs=None):
        self.cutoffs = cutoffs or {
            "excellent": 0.8,
            "trusted": 0.65,
            "suspicious": 0.5,
            "compromised": 0.35,
        }

    def classify_all(self, network):
        labels = {}
        for nid, node in network.nodes.items():
            if not node.alive:
                continue
            trust = node.trust_score
            if trust > self.cutoffs["excellent"]:
                label = "Excellent"
            elif trust > self.cutoffs["trusted"]:
                label = "Trusted"
            elif trust > self.cutoffs["suspicious"]:
                label = "Suspicious"
            elif trust > self.cutoffs["compromised"]:
                label = "Compromised"
            else:
                label = "Quarantined"
            node.record_classification(label)
            labels[nid] = label
        return {"labels": labels, "median": float("nan"), "mad": float("nan")}
