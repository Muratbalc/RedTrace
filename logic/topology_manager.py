"""
Topology management module built on top of NetworkX.

This module exposes the TopologyManager class, responsible for maintaining
the device graph, links, and layout positions for visualization.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import networkx as nx


@dataclass
class Device:
    """Simple data holder for device properties."""

    device_type: str
    hostname: str
    ip_address: str
    position: Tuple[float, float] = (0.0, 0.0)


class TopologyManager:
    """
    Encapsulates an undirected NetworkX graph representing the topology.

    Nodes store Device data. Edges store link metadata (e.g., type).
    """

    def __init__(self) -> None:
        self._graph: nx.Graph = nx.Graph()
        self._device_counter: int = 1

    # ------------------------------------------------------------------ #
    # Device operations

    def add_device(
        self,
        device_type: str,
        hostname: str,
        ip_address: str,
        position: Optional[Tuple[float, float]] = None,
    ) -> str:
        """Create a new device node and return its identifier."""
        node_id = f"device_{self._device_counter}"
        self._device_counter += 1

        device = Device(
            device_type=device_type,
            hostname=hostname,
            ip_address=ip_address,
            position=position if position is not None else (0.0, 0.0),
        )
        self._graph.add_node(node_id, **device.__dict__)
        return node_id

    def remove_device(self, node_id: str) -> None:
        """Remove a device node. Raises KeyError if the node does not exist."""
        if node_id not in self._graph:
            raise KeyError(f"Device '{node_id}' not found.")
        self._graph.remove_node(node_id)

    def update_device(
        self,
        node_id: str,
        *,
        device_type: Optional[str] = None,
        hostname: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Update device attributes."""
        if node_id not in self._graph:
            raise KeyError(f"Device '{node_id}' not found.")

        if device_type is not None:
            self._graph.nodes[node_id]["device_type"] = device_type
        if hostname is not None:
            self._graph.nodes[node_id]["hostname"] = hostname
        if ip_address is not None:
            self._graph.nodes[node_id]["ip_address"] = ip_address

    def set_device_position(
        self, node_id: str, position: Tuple[float, float]
    ) -> None:
        """Persist a manually chosen position for a device."""
        if node_id not in self._graph:
            raise KeyError(f"Device '{node_id}' not found.")
        clamped = (
            max(0.0, min(1.0, float(position[0]))),
            max(0.0, min(1.0, float(position[1]))),
        )
        self._graph.nodes[node_id]["position"] = clamped

    def get_devices(self) -> Dict[str, Dict[str, object]]:
        """Return a mapping of node_id -> device attributes."""
        return dict(self._graph.nodes(data=True))

    # ------------------------------------------------------------------ #
    # Link operations

    def add_link(
        self, source: str, target: str, link_type: str = "wired"
    ) -> None:
        """Create a link between two devices."""
        self._ensure_nodes_exist([source, target])
        if source == target:
            raise ValueError("Cannot connect a node to itself.")
        if self._graph.has_edge(source, target):
            raise ValueError("Link already exists between nodes.")

        self._graph.add_edge(source, target, link_type=link_type)

    def remove_link(self, source: str, target: str) -> None:
        """Remove an existing link."""
        if not self._graph.has_edge(source, target):
            raise KeyError("Link does not exist between nodes.")
        self._graph.remove_edge(source, target)

    def get_links(self) -> List[Tuple[str, str, Dict[str, object]]]:
        """Return list of edges with attributes."""
        return list(self._graph.edges(data=True))

    # ------------------------------------------------------------------ #
    # Layout & serialization

    def compute_layout(self) -> Dict[str, Tuple[float, float]]:
        """
        Compute a spring layout and persist node positions.

        Existing positions are used as hints to provide stable layouts.
        """
        if not self._graph.nodes:
            return {}

        current_pos = {
            node_id: data.get("position", (0.5, 0.5))
            for node_id, data in self._graph.nodes(data=True)
        }
        layout = nx.spring_layout(self._graph, pos=current_pos, seed=42)

        xs = [pos[0] for pos in layout.values()]
        ys = [pos[1] for pos in layout.values()]
        min_x, max_x = min(xs, default=0.0), max(xs, default=1.0)
        min_y, max_y = min(ys, default=0.0), max(ys, default=1.0)
        span_x = max(max_x - min_x, 1e-9)
        span_y = max(max_y - min_y, 1e-9)

        normalized_layout = {
            node_id: (
                (pos[0] - min_x) / span_x,
                (pos[1] - min_y) / span_y,
            )
            for node_id, pos in layout.items()
        }

        for node_id, pos in normalized_layout.items():
            self._graph.nodes[node_id]["position"] = (
                float(pos[0]),
                float(pos[1]),
            )
        return normalized_layout

    def to_dict(self) -> Dict[str, object]:
        """Serialize topology into a JSON-compatible dictionary."""
        nodes = [
            {
                "id": node_id,
                **data,
            }
            for node_id, data in self._graph.nodes(data=True)
        ]
        links = [
            {
                "source": source,
                "target": target,
                **data,
            }
            for source, target, data in self._graph.edges(data=True)
        ]
        return {"nodes": nodes, "links": links}

    def load_from_dict(self, payload: Dict[str, object]) -> None:
        """Load topology state from a serialized dictionary."""
        self._graph.clear()
        nodes = payload.get("nodes", [])
        links = payload.get("links", [])

        for entry in nodes:
            node_id = entry["id"]
            node_data = {
                key: entry[key]
                for key in ("device_type", "hostname", "ip_address")
                if key in entry
            }
            position = entry.get("position", (0.5, 0.5))
            node_data["position"] = (
                max(0.0, min(1.0, float(position[0]))),
                max(0.0, min(1.0, float(position[1]))),
            )
            self._graph.add_node(node_id, **node_data)

            # Keep device counter ahead of any provided IDs
            try:
                suffix = int(node_id.split("_")[-1])
                self._device_counter = max(self._device_counter, suffix + 1)
            except (ValueError, IndexError):
                # Non-standard ID, ignore for counter purposes
                continue

        for link in links:
            source = link["source"]
            target = link["target"]
            data = {"link_type": link.get("link_type", "wired")}
            self._graph.add_edge(source, target, **data)

    # ------------------------------------------------------------------ #
    # Helpers

    def _ensure_nodes_exist(self, nodes: Iterable[str]) -> None:
        missing = [node for node in nodes if node not in self._graph]
        if missing:
            raise KeyError(f"Unknown nodes: {', '.join(missing)}")


__all__ = ["TopologyManager", "Device"]

