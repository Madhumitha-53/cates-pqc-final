"""
authentication.py
-------------------
Module 7: Self-Adaptive Security Engine.

Decides, per node per round, which authentication mechanism to use based
on the node's trust classification:

    Excellent / Trusted   -> Lightweight authentication (cheap, fast)
    Suspicious/Compromised-> Post-Quantum (ML-DSA simulated) authentication
    Quarantined            -> Removed from routing (no authentication cost)

Costs (as specified in the framework):
    Lightweight : 5 ms latency,  1 unit energy
    PQC (ML-DSA): 50 ms latency, 5 units energy

This module also supports three baseline strategies used for comparison
in the performance evaluation (Module 9/10):
    - "none"       : no authentication at all
    - "always_pqc" : always use PQC regardless of trust
    - "trust_fixed": traditional trust-based auth with a FIXED threshold
    - "cates_pqc"  : the proposed adaptive scheme (uses classification)
"""

LIGHTWEIGHT_LATENCY_MS = 5.0
LIGHTWEIGHT_ENERGY = 1.0
PQC_LATENCY_MS = 50.0
PQC_ENERGY = 5.0

FIXED_TRUST_THRESHOLD = 0.5  # used only by the "trust_fixed" baseline

# Session validity windows (in rounds) for the proposed CATES-PQC scheme.
# A node that has just proven itself Excellent/Trusted is not forced
# through a brand-new heavyweight handshake on every single subsequent
# packet -- it keeps a short-lived lightweight session, exactly like a
# real TLS/PQC session-resumption mechanism. Suspicious/Compromised nodes
# are re-checked far more aggressively (little to no caching benefit),
# which is what makes the scheme "self-adaptive": trust that has been
# earned reduces future overhead, suspicion increases scrutiny.
SESSION_LENGTH = {
    "Excellent": 8,
    "Trusted": 4,
    "Suspicious": 1,
    "Compromised": 0,
}

# Labels that receive lightweight authentication under CATES-PQC. The
# "Suspicious" band (by construction of the median/MAD scheme) covers the
# broad, uncertain middle of the trust distribution and commonly still
# contains legitimate nodes experiencing ordinary behavioural noise -- so
# it is watched more closely (short session validity) rather than being
# immediately escalated to full PQC. Only nodes that have crossed further
# into "Compromised" territory are treated as confirmed threats requiring
# the heavyweight PQC handshake on every event.
LIGHTWEIGHT_LABELS = ("Excellent", "Trusted", "Suspicious")


class SelfAdaptiveSecurityEngine:
    def __init__(self, method="cates_pqc"):
        """
        method one of: 'none', 'always_pqc', 'trust_fixed', 'cates_pqc'
        """
        self.method = method

    def authenticate(self, node, classification_label=None, round_num=None):
        """Perform (simulated) authentication for a node and return a dict
        of costs incurred + which mechanism was used, or None if the node
        was skipped (quarantined / no-security baseline / cached session).
        """
        if not node.alive:
            return None

        if self.method == "none":
            return {"mechanism": "none", "latency_ms": 0.0, "energy": 0.0}

        if self.method == "always_pqc":
            node.pqc_auth_count += 1
            node.consume_energy(PQC_ENERGY)
            node.total_auth_latency_ms += PQC_LATENCY_MS
            node.total_auth_energy += PQC_ENERGY
            return {"mechanism": "pqc", "latency_ms": PQC_LATENCY_MS, "energy": PQC_ENERGY}

        if self.method == "trust_fixed":
            # Traditional scheme: simple per-event check, no session reuse.
            if node.trust_score >= FIXED_TRUST_THRESHOLD:
                node.lightweight_auth_count += 1
                node.consume_energy(LIGHTWEIGHT_ENERGY)
                node.total_auth_latency_ms += LIGHTWEIGHT_LATENCY_MS
                node.total_auth_energy += LIGHTWEIGHT_ENERGY
                return {"mechanism": "lightweight", "latency_ms": LIGHTWEIGHT_LATENCY_MS,
                        "energy": LIGHTWEIGHT_ENERGY}
            else:
                node.pqc_auth_count += 1
                node.consume_energy(PQC_ENERGY)
                node.total_auth_latency_ms += PQC_LATENCY_MS
                node.total_auth_energy += PQC_ENERGY
                return {"mechanism": "pqc", "latency_ms": PQC_LATENCY_MS, "energy": PQC_ENERGY}

        # ---------------- Proposed CATES-PQC: adaptive, session-aware ----------------
        if classification_label == "Quarantined" or classification_label is None:
            return None

        # Reuse a still-valid lightweight session if one exists.
        if round_num is not None and node.session_valid_until >= round_num:
            return {"mechanism": "cached", "latency_ms": 0.0, "energy": 0.0}

        if classification_label in LIGHTWEIGHT_LABELS:
            node.lightweight_auth_count += 1
            node.consume_energy(LIGHTWEIGHT_ENERGY)
            node.total_auth_latency_ms += LIGHTWEIGHT_LATENCY_MS
            node.total_auth_energy += LIGHTWEIGHT_ENERGY
            if round_num is not None:
                node.session_valid_until = round_num + SESSION_LENGTH[classification_label]
            return {"mechanism": "lightweight", "latency_ms": LIGHTWEIGHT_LATENCY_MS,
                    "energy": LIGHTWEIGHT_ENERGY}
        else:  # Compromised -- confirmed threat, full PQC every event
            node.pqc_auth_count += 1
            node.consume_energy(PQC_ENERGY)
            node.total_auth_latency_ms += PQC_LATENCY_MS
            node.total_auth_energy += PQC_ENERGY
            if round_num is not None:
                node.session_valid_until = round_num + SESSION_LENGTH[classification_label]
            return {"mechanism": "pqc", "latency_ms": PQC_LATENCY_MS, "energy": PQC_ENERGY}
