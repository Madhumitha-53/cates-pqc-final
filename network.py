"""
network.py
-----------
Module 1: IoT Network Generator.

Builds a random wireless IoT topology using NetworkX, populates it with
IoTNode objects (80% normal / 20% malicious), and exposes helper methods
used by the rest of the pipeline (neighbour queries, alive-node filtering,
edge-weight updates for trust-aware routing).
"""

import networkx as nx
import numpy as np

from node import IoTNode


class IoTNetwork:
    def __init__(self, num_nodes=100, malicious_ratio=0.2, connect_radius=0.18,
                 seed=42, initial_energy_range=(50, 100), attack_mode="constant",
                 p_good=0.5, normal_drop_probability=0.02,
                 behavior_config=None):
        self.num_nodes = num_nodes
        self.malicious_ratio = malicious_ratio
        self.seed = seed
        self.initial_energy_range = initial_energy_range
        self.attack_mode = attack_mode
        self.p_good = p_good
        self.normal_drop_probability = normal_drop_probability
        self.behavior_config = behavior_config
        self.rng = np.random.default_rng(seed)

        self.graph = nx.Graph()
        self.nodes = {}          # node_id -> IoTNode
        self.positions = {}      # node_id -> (x, y) for a geometric topology

        self._build_topology(connect_radius)
        edges = list(self.graph.edges)
        self._edge_sources = np.asarray([u for u, _ in edges], dtype=int)
        self._edge_targets = np.asarray([v for _, v in edges], dtype=int)
        self._degrees = np.asarray(
            [self.graph.degree(nid) for nid in range(self.num_nodes)], dtype=float
        )
        self._populate_nodes()

    # ------------------------------------------------------------------
    def _build_topology(self, radius):
        """Random geometric graph -> realistic wireless connectivity.

        Falls back to increasing the radius if the graph is disconnected,
        so routing always has a path between any two alive nodes.
        """
        r = radius
        for _ in range(20):
            g = nx.random_geometric_graph(self.num_nodes, r, seed=self.seed)
            if nx.is_connected(g):
                self.graph = g
                break
            r += 0.02
        else:
            self.graph = g  # best effort; largest component used later

        self.positions = nx.get_node_attributes(self.graph, "pos")
        if not self.positions:
            self.positions = {n: (self.rng.uniform(0, 1), self.rng.uniform(0, 1))
                               for n in self.graph.nodes}

        # Initialize base edge weight = Euclidean distance
        for u, v in self.graph.edges:
            px, py = self.positions[u]
            qx, qy = self.positions[v]
            dist = float(np.hypot(px - qx, py - qy))
            self.graph[u][v]["distance"] = dist
            self.graph[u][v]["weight"] = dist  # will be updated by routing engine

    def _populate_nodes(self):
        node_ids = list(self.graph.nodes)
        self.rng.shuffle(node_ids)
        n_malicious = int(round(self.num_nodes * self.malicious_ratio))
        malicious_set = set(node_ids[:n_malicious])

        for nid in self.graph.nodes:
            is_mal = nid in malicious_set
            node = IoTNode(
                node_id=nid,
                node_type="malicious" if is_mal else "normal",
                is_malicious=is_mal,
                energy=self.rng.uniform(*self.initial_energy_range),
                initial_trust=0.5,
                rng=self.rng,
                attack_mode=self.attack_mode,
                p_good=self.p_good,
                normal_drop_probability=self.normal_drop_probability,
                behavior_config=self.behavior_config,
            )
            self.nodes[nid] = node

    # ------------------------------------------------------------------
    def neighbours(self, node_id):
        if node_id not in self.graph:
            return []
        return list(self.graph.neighbors(node_id))

    def alive_nodes(self):
        return [nid for nid, n in self.nodes.items() if n.alive and not n.quarantined]

    def malicious_ids(self):
        return [nid for nid, n in self.nodes.items() if n.is_malicious]

    def normal_ids(self):
        return [nid for nid, n in self.nodes.items() if not n.is_malicious]

    def average_neighbour_trust(self, node_id):
        nbrs = self.neighbours(node_id)
        if not nbrs:
            return 0.5
        return sum(self.nodes[n].trust_score for n in nbrs) / len(nbrs)

    def neighbour_trust_means(self):
        trust = np.fromiter(
            (self.nodes[nid].trust_score for nid in range(self.num_nodes)),
            dtype=float, count=self.num_nodes,
        )
        totals = np.bincount(
            np.concatenate((self._edge_sources, self._edge_targets)),
            weights=np.concatenate((trust[self._edge_targets], trust[self._edge_sources])),
            minlength=self.num_nodes,
        )
        means = np.full(self.num_nodes, 0.5, dtype=float)
        np.divide(totals, self._degrees, out=means, where=self._degrees > 0)
        return means

    def network_congestion(self, active_traffic_ratio):
        """Simple network-wide congestion proxy in [0, 1]."""
        return float(np.clip(active_traffic_ratio, 0.0, 1.0))

    def alive_fraction(self):
        return sum(node.alive for node in self.nodes.values()) / self.num_nodes
