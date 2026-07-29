"""
routing.py
-----------
Module 8: Trust-Aware Routing.

Builds routing edge weights as:
    edge_cost(u, v) = distance(u, v) + trust_penalty(u, v)

where trust_penalty grows as either endpoint's trust score drops, strongly
discouraging (but not always forbidding) paths through suspicious nodes.
Quarantined nodes are removed from the routing graph entirely; compromised
nodes are heavily penalized but still routable if no alternative exists.

Shortest paths are computed with NetworkX (Dijkstra via nx.shortest_path).
"""

import networkx as nx

TRUST_PENALTY_WEIGHT = 5.0   # scales how strongly low trust inflates cost


class TrustAwareRouter:
    def __init__(self, network):
        self.network = network

    def _build_routable_graph(self, trust_aware=True, respect_quarantine=True):
        g = self.network.graph
        nodes = self.network.nodes

        if respect_quarantine:
            alive_ids = set(self.network.alive_nodes())  # excludes quarantined & dead
        else:
            alive_ids = {nid for nid, n in nodes.items() if n.alive}

        routable = nx.Graph()
        routable.add_nodes_from(alive_ids)

        for u, v, data in g.edges(data=True):
            if u not in alive_ids or v not in alive_ids:
                continue
            dist = data.get("distance", 1.0)
            if trust_aware:
                trust_u = nodes[u].trust_score
                trust_v = nodes[v].trust_score
                avg_trust = (trust_u + trust_v) / 2.0
                trust_penalty = TRUST_PENALTY_WEIGHT * (1.0 - avg_trust)
                cost = dist + trust_penalty
            else:
                cost = dist
            routable.add_edge(u, v, weight=cost)

        return routable

    def find_path(self, source, destination, trust_aware=True, respect_quarantine=True):
        """Compute a route from source to destination.

        trust_aware=True adds a trust penalty term to edge costs (module 8);
        respect_quarantine=True removes quarantined nodes from the graph
        entirely (used by the proposed CATES-PQC scheme). Baseline methods
        can disable either behaviour for a fair comparison.
        """
        routable = self._build_routable_graph(trust_aware=trust_aware,
                                               respect_quarantine=respect_quarantine)
        if source not in routable or destination not in routable:
            return False, None
        try:
            path = nx.shortest_path(routable, source=source, target=destination,
                                     weight="weight")
            return True, path
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return False, None

