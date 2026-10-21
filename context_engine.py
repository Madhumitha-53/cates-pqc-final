"""
context_engine.py
------------------
Module 3: Context Engine.

Tracks network-wide contextual parameters each round:
    - congestion        : traffic load on the network
    - energy_availability: average residual energy across alive nodes
    - threat_level       : estimated fraction of suspicious/compromised activity
    - neighbour_behaviour: average neighbour consensus across the network

These context values feed the Dynamic Weight Engine (module 4), which
adjusts trust-feature importance in real time.
"""

import numpy as np


class ContextEngine:
    def __init__(self, network, threat_ema_alpha=0.3):
        self.network = network
        self.threat_ema_alpha = threat_ema_alpha
        self.smoothed_threat_level = 0.0
        self.history = []

    def update(self, round_num, traffic_ratio, neighbour_trusts=None):
        nodes = self.network.nodes

        alive_ids = [nid for nid, node in nodes.items() if node.alive]
        if alive_ids:
            energy_availability = float(np.mean(
                [nodes[n].energy / nodes[n].max_energy for n in alive_ids]
            ))
        else:
            energy_availability = 0.0

        congestion = self.network.network_congestion(traffic_ratio)

        # Estimate threat only from observable classifications, never evaluation labels.
        flagged_count = sum(
            nodes[nid].security_class in ("Compromised", "Quarantined")
            for nid in alive_ids
        )
        observed_threat = flagged_count / len(alive_ids) if alive_ids else 0.0
        self.smoothed_threat_level = (
            self.threat_ema_alpha * observed_threat
            + (1.0 - self.threat_ema_alpha) * self.smoothed_threat_level
        )
        threat_level = float(np.clip(self.smoothed_threat_level, 0.0, 1.0))

        if alive_ids:
            if neighbour_trusts is None:
                neighbour_trusts = self.network.neighbour_trust_means()
            neighbour_behaviour = float(np.mean(
                [neighbour_trusts[n] for n in alive_ids]
            ))
        else:
            neighbour_behaviour = 0.5

        context = {
            "round": round_num,
            "congestion": congestion,
            "energy_availability": energy_availability,
            "threat_level": threat_level,
            "neighbour_behaviour": neighbour_behaviour,
        }
        self.history.append(context)
        return context
