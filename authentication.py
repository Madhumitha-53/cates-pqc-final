"""
Module 7: Self-Adaptive Security Engine.

Authentication costs are simulated rather than implemented with a
cryptographic library: lightweight is 5 ms / 1 energy unit, and PQC is
50 ms / 5 energy units.
"""

LIGHTWEIGHT_LATENCY_MS = 5.0
LIGHTWEIGHT_ENERGY = 1.0
PQC_LATENCY_MS = 50.0
PQC_ENERGY = 5.0
FIXED_TRUST_THRESHOLD = 0.5

SESSION_LENGTH = {
    "Excellent": 8,
    "Trusted": 4,
    "Suspicious": 1,
    "Compromised": 0,
}
LIGHTWEIGHT_LABELS = ("Excellent", "Trusted", "Suspicious")


class SelfAdaptiveSecurityEngine:
    def __init__(self, method="cates_pqc", session_lengths=None,
                 respect_quarantine=True, fixed_threshold=FIXED_TRUST_THRESHOLD,
                 lightweight_latency_ms=LIGHTWEIGHT_LATENCY_MS,
                 lightweight_energy=LIGHTWEIGHT_ENERGY,
                 pqc_latency_ms=PQC_LATENCY_MS, pqc_energy=PQC_ENERGY):
        self.method = method
        self.session_lengths = dict(session_lengths or SESSION_LENGTH)
        self.respect_quarantine = respect_quarantine
        self.fixed_threshold = fixed_threshold
        self.lightweight_latency_ms = lightweight_latency_ms
        self.lightweight_energy = lightweight_energy
        self.pqc_latency_ms = pqc_latency_ms
        self.pqc_energy = pqc_energy

    def _charge(self, node, mechanism):
        if mechanism == "lightweight":
            latency, energy = self.lightweight_latency_ms, self.lightweight_energy
            node.lightweight_auth_count += 1
        else:
            latency, energy = self.pqc_latency_ms, self.pqc_energy
            node.pqc_auth_count += 1
        node.consume_energy(energy)
        node.total_auth_latency_ms += latency
        node.total_auth_energy += energy
        return {"mechanism": mechanism, "latency_ms": latency, "energy": energy}

    def authenticate(self, node, classification_label=None, round_num=None):
        """Return authentication costs, or None if authentication is skipped."""
        if not node.alive:
            return None
        if self.method == "none":
            return {"mechanism": "none", "latency_ms": 0.0, "energy": 0.0}
        if self.method == "always_pqc":
            return self._charge(node, "pqc")
        if self.method in ("trust_fixed", "trust_fixed_cached", "trust_fixed_routing"):
            lightweight = node.trust_score >= self.fixed_threshold
            if lightweight and self.method == "trust_fixed_cached" \
                    and round_num is not None and node.session_valid_until >= round_num:
                return {"mechanism": "cached", "latency_ms": 0.0, "energy": 0.0}
            if lightweight and self.method == "trust_fixed_cached" and round_num is not None:
                cache_label = classification_label
                if cache_label not in LIGHTWEIGHT_LABELS:
                    cache_label = "Trusted"
                node.session_valid_until = (
                    round_num + self.session_lengths[cache_label]
                )
            return self._charge(node, "lightweight" if lightweight else "pqc")

        if classification_label is None:
            return None
        if self.respect_quarantine and classification_label == "Quarantined":
            return None
        if classification_label in LIGHTWEIGHT_LABELS:
            if round_num is not None and node.session_valid_until >= round_num:
                return {"mechanism": "cached", "latency_ms": 0.0, "energy": 0.0}
            result = self._charge(node, "lightweight")
            if round_num is not None:
                node.session_valid_until = (
                    round_num + self.session_lengths.get(classification_label, 0)
                )
            return result
        result = self._charge(node, "pqc")
        if round_num is not None:
            node.session_valid_until = (
                round_num + self.session_lengths.get(classification_label, 0)
            )
        return result
