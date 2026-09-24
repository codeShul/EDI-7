"""Graph-based route management.

Models the 5-node full mesh (10 links) as a NetworkX graph. Isolating a node
removes it from the graph so alternate paths can be (re)computed for every
affected pair; restoring it re-adds the node and its original edges.
"""
from __future__ import annotations

from typing import Optional

import networkx as nx


class RecoveryController:
    def __init__(self, node_ids: list[int]):
        self._base_graph = nx.complete_graph(node_ids)
        self.graph = self._base_graph.copy()
        self.isolated: set[int] = set()

    def all_nodes(self) -> list[int]:
        return sorted(self._base_graph.nodes)

    def total_links(self) -> int:
        return self._base_graph.number_of_edges()

    def isolate(self, node_id: int) -> None:
        self.isolated.add(node_id)
        if self.graph.has_node(node_id):
            self.graph.remove_node(node_id)

    def restore(self, node_id: int) -> None:
        self.isolated.discard(node_id)
        if not self._base_graph.has_node(node_id):
            return  # e.g. an unregistered (rogue) node that was blocked but never part of the mesh
        if not self.graph.has_node(node_id):
            self.graph.add_node(node_id)
            for neighbor in self._base_graph.neighbors(node_id):
                if self.graph.has_node(neighbor):
                    self.graph.add_edge(node_id, neighbor)

    def find_route(self, source: int, destination: int) -> Optional[list[int]]:
        if source not in self.graph or destination not in self.graph:
            return None
        try:
            return nx.shortest_path(self.graph, source, destination)
        except nx.NetworkXNoPath:
            return None

    def all_routes(self) -> list[dict]:
        nodes = self.all_nodes()
        routes = []
        for i, source in enumerate(nodes):
            for destination in nodes[i + 1:]:
                path = self.find_route(source, destination)
                routes.append({
                    "source": source,
                    "destination": destination,
                    "path": path,
                    "status": "ACTIVE" if path else "DOWN",
                })
        return routes

    def status(self) -> dict:
        return {
            "isolated_nodes": sorted(self.isolated),
            "active_links": self.graph.number_of_edges(),
            "total_links": self.total_links(),
        }
