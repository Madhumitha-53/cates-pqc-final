"""
node.py
--------
Defines the IoTNode class used across the CATES-PQC simulation.

Each node carries:
    - static identity (node_id, node_type, malicious flag)
    - dynamic state (energy, trust score, trust history)
    - per-round behavioural feature vector Ni

Feature vector Ni (see paper Section III-B):
    Ni = [ PFR, PAID, CI, RE, CL, NC ]
        PFR  -> Packet Forwarding Rate
        PAID -> Packet Arrival Interval Deviation
        CI   -> Cryptographic Integrity
        RE   -> Residual Energy (normalized)
        CL   -> Congestion Level
        NC   -> Neighbour Consensus
"""

import numpy as np


class IoTNode:
    """Represents a single IoT device in the network."""

    def __init__(self, node_id, node_type="normal", is_malicious=False,
                 energy=None, initial_trust=0.5, rng=None):
        self.rng = rng if rng is not None else np.random.default_rng()

        self.node_id = node_id
        self.node_type = node_type              # "normal" or "malicious"
        self.is_malicious = is_malicious

        # Energy in [50, 100] units unless explicitly supplied
        self.energy = energy if energy is not None else self.rng.uniform(50, 100)
        self.initial_energy = self.energy
        self.max_energy = 100.0

        # Trust
        self.trust_score = initial_trust
        self.trust_history = [initial_trust]

        # Security / classification state
        self.security_class = "Trusted"         # Excellent/Trusted/Suspicious/Compromised/Quarantined
        self.classification_history = ["Trusted"]
        self.quarantined = False

        # Latest behavioural feature vector
        self.features = {
            "pfr": 1.0,
            "paid": 0.0,
            "ci": 1.0,
            "re": 1.0,
            "cl": 0.0,
            "nc": 1.0,
        }

        # Session-based authentication caching (self-adaptive security
        # engine): a node that has recently proven itself Excellent/Trusted
        # keeps a valid lightweight session for several rounds instead of
        # re-authenticating from scratch every single communication event.
        # Suspicious/Compromised nodes get little or no caching benefit.
        self.session_valid_until = 0

        # Bookkeeping counters (used by metrics.py)
        self.packets_sent = 0
        self.packets_delivered = 0
        self.lightweight_auth_count = 0
        self.pqc_auth_count = 0
        self.total_auth_latency_ms = 0.0
        self.total_auth_energy = 0.0
        self.alive = True

    # ------------------------------------------------------------------
    # Feature generation
    # ------------------------------------------------------------------
    def generate_features(self, congestion_level, neighbour_consensus):
        """Generate a realistic per-round feature vector Ni.

        Malicious nodes produce degraded values (packet dropping, higher
        delay/jitter, poor crypto integrity, abnormal patterns).
        Normal nodes produce values with small random noise.
        """
        if self.is_malicious:
            pfr = self.rng.uniform(0.1, 0.5)
            paid = self.rng.uniform(0.4, 1.0)      # high deviation
            ci = self.rng.uniform(0.0, 0.5)
        else:
            pfr = self.rng.uniform(0.8, 1.0)
            paid = self.rng.uniform(0.0, 0.15)     # low deviation
            ci = 1.0

        # Residual energy normalized to [0, 1]
        re = max(self.energy, 0.0) / self.max_energy

        # Congestion is a shared/contextual value with small per-node noise
        cl = float(np.clip(congestion_level + self.rng.normal(0, 0.03), 0, 1))

        # Neighbour consensus: malicious nodes tend to disagree with neighbours
        if self.is_malicious:
            nc = float(np.clip(neighbour_consensus - self.rng.uniform(0.2, 0.5), 0, 1))
        else:
            nc = float(np.clip(neighbour_consensus + self.rng.normal(0, 0.05), 0, 1))

        self.features = {
            "pfr": pfr, "paid": paid, "ci": ci,
            "re": re, "cl": cl, "nc": nc,
        }
        return self.features

    # ------------------------------------------------------------------
    def consume_energy(self, amount):
        """Deduct energy for a communication / authentication event."""
        self.energy = max(0.0, self.energy - amount)
        if self.energy <= 0.0:
            self.alive = False

    def record_trust(self, new_trust):
        self.trust_score = float(np.clip(new_trust, 0.0, 1.0))
        self.trust_history.append(self.trust_score)

    def record_classification(self, label):
        self.security_class = label
        self.classification_history.append(label)
        self.quarantined = (label == "Quarantined")

    def __repr__(self):
        return (f"IoTNode(id={self.node_id}, type={self.node_type}, "
                f"trust={self.trust_score:.3f}, energy={self.energy:.1f}, "
                f"class={self.security_class})")
