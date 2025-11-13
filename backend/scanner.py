"""
Network scanning utilities for building a topology graph.

The scanner attempts to use python-nmap (if installed) to discover active
hosts on the configured subnet. If scanning fails or the dependency is
missing, the module falls back to returning a curated sample topology so the
frontend can still function during development.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    import nmap  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    nmap = None  # type: ignore


Topology = Dict[str, List[Dict[str, Any]]]


SAMPLE_TOPOLOGY: Topology = {
    "nodes": [
        {"id": "192.168.1.1", "label": "Core Router", "type": "router"},
        {"id": "192.168.1.10", "label": "Office Switch", "type": "switch"},
        {"id": "192.168.1.24", "label": "Engineering-PC", "type": "client"},
        {"id": "192.168.1.42", "label": "QA-Laptop", "type": "client"},
        {"id": "192.168.1.60", "label": "Printer-1", "type": "printer"},
        {"id": "192.168.1.80", "label": "NAS-Storage", "type": "server"},
    ],
    "edges": [
        {"from": "192.168.1.1", "to": "192.168.1.10"},
        {"from": "192.168.1.10", "to": "192.168.1.24"},
        {"from": "192.168.1.10", "to": "192.168.1.42"},
        {"from": "192.168.1.1", "to": "192.168.1.60"},
        {"from": "192.168.1.1", "to": "192.168.1.80"},
    ],
}


DEVICE_TYPE_COLORS = {
    "router": "#ff4d4f",
    "switch": "#fa8c16",
    "server": "#9254de",
    "printer": "#13c2c2",
    "client": "#1890ff",
    "iot": "#52c41a",
    "unknown": "#8c8c8c",
}


@dataclass
class CacheEntry:
    topology: Topology
    timestamp: float


class TopologyCache:
    """In-memory TTL cache for scan results."""

    def __init__(self, ttl_seconds: int = 60) -> None:
        self.ttl_seconds = ttl_seconds
        self._entry: Optional[CacheEntry] = None

    def get(self) -> Optional[Topology]:
        if not self._entry:
            return None
        if time.time() - self._entry.timestamp > self.ttl_seconds:
            self._entry = None
            return None
        return self._entry.topology

    def set(self, topology: Topology) -> None:
        self._entry = CacheEntry(topology=topology, timestamp=time.time())

    def clear(self) -> None:
        self._entry = None


class NetworkScanner:
    """High-level network scanner producing a topology graph representation."""

    def __init__(
        self,
        subnet: str = "192.168.1.0/24",
        ports: str = "1-1024",
        auto_fallback: bool = True,
        cache_ttl: int = 60,
    ) -> None:
        self.subnet = subnet
        self.ports = ports
        self.auto_fallback = auto_fallback
        self.cache = TopologyCache(ttl_seconds=cache_ttl)

    # ------------------------------------------------------------------ #
    # Public API

    def scan(self, force: bool = False) -> Topology:
        """Return the current topology graph, optionally forcing a re-scan."""
        if not force:
            cached = self.cache.get()
            if cached:
                return cached

        try:
            topology = self._scan_with_nmap()
            self.cache.set(topology)
            return topology
        except Exception:  # pragma: no cover - scan errors are non-deterministic
            if not self.auto_fallback:
                raise
            self.cache.set(SAMPLE_TOPOLOGY)
            return SAMPLE_TOPOLOGY

    # ------------------------------------------------------------------ #
    # Internal helpers

    def _scan_with_nmap(self) -> Topology:
        if nmap is None:
            raise RuntimeError("python-nmap is not installed.")

        nm = nmap.PortScanner()
        # TCP connect scan to avoid root requirement, include host discovery.
        nm.scan(hosts=self.subnet, arguments=f"-sT -T4 -p {self.ports}")

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        gateway_ip = self._pick_gateway_ip()
        device_map: Dict[str, Dict[str, Any]] = {}

        for host in nm.all_hosts():
            state = nm[host].state()
            if state != "up":
                continue

            addresses = nm[host].get("addresses", {})
            mac = addresses.get("mac")
            vendor = self._extract_vendor(nm[host])
            hostname = self._extract_hostname(nm[host]) or host
            ports = self._extract_open_ports(nm[host])

            device_type = self._infer_device_type(hostname, vendor, ports)
            label = self._compose_label(hostname, device_type)

            node = {
                "id": host,
                "label": label,
                "type": device_type,
                "mac": mac,
                "vendor": vendor,
                "ports": ports,
            }
            nodes.append(node)
            device_map[host] = node

        # Simple heuristics for edges: connect hosts to gateway if available,
        # otherwise create a star topology anchored at the lowest IP.
        if not nodes:
            return {"nodes": nodes, "edges": edges}

        anchor_id = gateway_ip if any(node["id"] == gateway_ip for node in nodes) else None
        if not anchor_id:
            anchor_id = min(nodes, key=lambda item: ipaddress.ip_address(item["id"]))["id"]

        for node in nodes:
            if node["id"] == anchor_id:
                continue
            edges.append({"from": anchor_id, "to": node["id"]})

        return {"nodes": nodes, "edges": edges}

    @staticmethod
    def _extract_open_ports(host_data: Any) -> List[int]:
        ports: List[int] = []
        for proto in host_data.all_protocols():
            for port in host_data[proto].keys():
                if host_data[proto][port]["state"] == "open":
                    ports.append(int(port))
        return sorted(set(ports))

    @staticmethod
    def _extract_vendor(host_data: Any) -> Optional[str]:
        try:
            vendors = host_data["vendor"]
            return next(iter(vendors.values())) if vendors else None
        except KeyError:
            return None

    @staticmethod
    def _extract_hostname(host_data: Any) -> Optional[str]:
        hostnames = host_data.get("hostnames") or []
        for entry in hostnames:
            if entry.get("name"):
                return entry["name"]
        return None

    @staticmethod
    def _compose_label(hostname: str, device_type: str) -> str:
        return f"{hostname} ({device_type.title()})"

    @staticmethod
    def _infer_device_type(
        hostname: str,
        vendor: Optional[str],
        ports: List[int],
    ) -> str:
        hostname_lower = hostname.lower()
        vendor_lower = vendor.lower() if vendor else ""

        if any(keyword in hostname_lower for keyword in ("router", "gateway", "gw")):
            return "router"
        if any(keyword in hostname_lower for keyword in ("switch", "sw")):
            return "switch"
        if any(keyword in hostname_lower for keyword in ("printer", "print")):
            return "printer"
        if any(keyword in hostname_lower for keyword in ("nas", "storage")):
            return "server"

        if vendor_lower:
            if any(name in vendor_lower for name in ("cisco", "juniper", "mikrotik", "ubiquiti")):
                return "router"
            if "hewlett" in vendor_lower or "hp" in vendor_lower:
                return "printer"
            if any(name in vendor_lower for name in ("intel", "asus", "lenovo", "dell")):
                return "client"

        if any(port in ports for port in (22, 3389, 5900)):
            return "server"
        if any(port in ports for port in (9100, 515)):
            return "printer"
        if any(port in ports for port in (80, 443, 53)):
            return "router"
        if not ports:
            return "client"

        return "unknown"

    def _pick_gateway_ip(self) -> Optional[str]:
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
            return str(next(network.hosts()))
        except Exception:
            return None


__all__ = ["NetworkScanner", "TopologyCache", "SAMPLE_TOPOLOGY"]

