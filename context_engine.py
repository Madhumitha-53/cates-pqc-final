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
    def __init__(self, network):
        self.network = network
        self.history = []

    def update(self, round_num, traffic_ratio, recent_detection_rate):
        nodes = self.network.nodes

        alive_ids = self.network.alive_nodes()
        if alive_ids:
            energy_availability = float(np.mean(
                [nodes[n].energy / nodes[n].max_energy for n in alive_ids]
            ))
        else:
            energy_availability = 0.0

        congestion = self.network.network_congestion(traffic_ratio)

        # Threat level = smoothed recent detection / suspicious rate
        threat_level = float(np.clip(recent_detection_rate, 0.0, 1.0))

        if alive_ids:
            neighbour_behaviour = float(np.mean(
                [self.network.average_neighbour_trust(n) for n in alive_ids]
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
