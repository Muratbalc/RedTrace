"""
FastAPI application for network topology discovery and visualization.

This backend performs automatic LAN device discovery using:
1. ARP discovery (Scapy with fallbacks to nmap/ARP table) to map IP -> MAC
2. Nmap port/service scanning with XML parsing, batching, and parallelization
3. Correlation of results into unified topology JSON

PERMISSIONS:
-----------
For full functionality, the process needs network capture privileges.

Option 1 - Run with sudo (simplest):
    sudo python -m uvicorn backend.main:app --reload
    # Or with venv:
    sudo ./venv/bin/python -m uvicorn backend.main:app --reload

Option 2 - Grant capabilities to Python (recommended for production):
    sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
    # Or for venv:
    sudo setcap cap_net_raw,cap_net_admin+eip /path/to/venv/bin/python3
    python -m uvicorn backend.main:app --reload

Without privileges, the backend will use fallback methods (nmap, ARP table)
and return sample data if all methods fail.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import netifaces  # type: ignore[import]
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from .arp_sniffer import discover_devices
from .port_scanner import quick_host_discovery, scan_hosts

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
FRONTEND_DIST = FRONTEND_DIR / "dist"

# Scan configuration defaults
DEFAULT_SWEEP_TIMEOUT = 2.0
DEFAULT_SNIFF_TIMEOUT = 5
DEFAULT_PORTS = "1-1024"  # Default port range (use "-" for all ports)
DEFAULT_TIMING = "T4"
DEFAULT_MIN_RATE = 100
DEFAULT_HOST_TIMEOUT = 30
DEFAULT_BATCH_SIZE = 50
DEFAULT_MAX_WORKERS = 4

# Fallback topology for testing without network access
FALLBACK_TOPOLOGY: Dict[str, Any] = {
    "nodes": [
        {
            "id": "192.168.1.1",
            "ip": "192.168.1.1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "router.local",
            "label": "Core Router",
            "type": "router",
            "ports": [
                {"port": 53, "state": "open", "service": "domain", "version": "dnsmasq"},
                {"port": 80, "state": "open", "service": "http", "version": "lighttpd"},
                {"port": 443, "state": "open", "service": "https", "version": ""},
            ],
        },
        {
            "id": "192.168.1.42",
            "ip": "192.168.1.42",
            "mac": "11:22:33:44:55:66",
            "hostname": "workstation.local",
            "label": "Workstation",
            "type": "client",
            "ports": [
                {"port": 22, "state": "open", "service": "ssh", "version": "OpenSSH 8.2"},
            ],
        },
        {
            "id": "192.168.1.100",
            "ip": "192.168.1.100",
            "mac": "22:33:44:55:66:77",
            "hostname": "",
            "label": "192.168.1.100",
            "type": "client",
            "ports": [],
        },
    ],
    "edges": [
        {"from": "192.168.1.1", "to": "192.168.1.42"},
        {"from": "192.168.1.1", "to": "192.168.1.100"},
    ],
}

app = FastAPI(title="Network Topology Visualizer", version="2.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Helper utilities
# --------------------------------------------------------------------------- #


def _resolve_primary_interface() -> tuple[str, Optional[str], Optional[ipaddress.IPv4Network]]:
    """
    Detect primary network interface and subnet.

    Prefers interface with default gateway, falls back to first non-loopback,
    non-virtual IPv4 interface.

    Returns
    -------
    Tuple of (interface_name, gateway_ip, network).
    """
    gateways = netifaces.gateways()
    default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)

    interface: Optional[str] = None
    gateway_ip: Optional[str] = None

    if default_gateway:
        gateway_ip, interface = default_gateway

    # Fallback: find first non-loopback, non-virtual interface
    if not interface:
        for candidate in netifaces.interfaces():
            if candidate.startswith("lo"):
                continue
            if any(
                candidate.startswith(prefix)
                for prefix in ("docker", "br-", "veth", "virbr", "vmnet", "tun", "tap")
            ):
                continue
            interface = candidate
            break

    if not interface:
        raise RuntimeError("Could not determine a primary network interface.")

    # Determine subnet from interface configuration
    network = None
    addresses = netifaces.ifaddresses(interface).get(netifaces.AF_INET, [])
    if addresses:
        addr = addresses[0].get("addr")
        netmask = addresses[0].get("netmask")
        if addr and netmask:
            try:
                network = ipaddress.IPv4Network(f"{addr}/{netmask}", strict=False)
            except Exception:
                pass

    if not network:
        raise RuntimeError(f"Could not determine subnet for interface {interface}.")

    logger.info(f"Detected interface: {interface}, gateway: {gateway_ip}, network: {network}")
    return interface, gateway_ip, network


def _infer_device_type(hostname: str, ports: List[Dict[str, Any]]) -> str:
    """Infer device type from hostname and open ports."""
    hostname_lower = (hostname or "").lower()
    port_numbers = {port_info["port"] for port_info in ports}
    service_names = {port_info.get("service", "").lower() for port_info in ports}

    if any(keyword in hostname_lower for keyword in ("router", "gw", "gateway", "modem")):
        return "router"
    if port_numbers.intersection({53, 80, 443}) and 22 not in port_numbers:
        return "router"

    if any(keyword in hostname_lower for keyword in ("switch", "sw")):
        return "switch"

    if any(keyword in hostname_lower for keyword in ("printer", "print")):
        return "printer"
    if 9100 in port_numbers or any("print" in svc for svc in service_names):
        return "printer"

    if port_numbers.intersection({445, 139, 3389}):
        return "server"
    if port_numbers.intersection({22, 80, 443, 3306, 5432}):
        return "server"

    return "client"


def _build_edges(nodes: Dict[str, Dict[str, Any]], gateway_ip: Optional[str]) -> List[Dict[str, str]]:
    """Build topology edges connecting all nodes to the gateway (star topology)."""
    edges: List[Dict[str, str]] = []
    anchor = gateway_ip if gateway_ip and gateway_ip in nodes else None
    if not anchor and nodes:
        anchor = next(iter(nodes.keys()))
    if not anchor:
        return edges
    for node_id in nodes:
        if node_id == anchor:
            continue
        edges.append({"from": anchor, "to": node_id})
    return edges


# --------------------------------------------------------------------------- #
# API endpoints (defined BEFORE static mounts to avoid shadowing)
# --------------------------------------------------------------------------- #


@app.get("/api/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "network-topology-visualizer"}


@app.get("/api/scan")
async def scan_network(
    timeout: int = Query(60, description="Overall scan timeout in seconds", ge=1, le=600),
    ports: str = Query(DEFAULT_PORTS, description="Port range (e.g., '1-1024', '22,80,443', '-' for all)"),
    debug: int = Query(0, description="Debug mode: 0=off, 1=include raw data", ge=0, le=1),
) -> Dict[str, Any]:
    """
    Combined network discovery endpoint with optimized nmap scanning.

    Performs:
    1. ARP discovery (with fallbacks) to map IP -> MAC
    2. Nmap port/service scan on discovered hosts (batched, parallelized)
    3. Correlation and device type inference
    4. Returns topology JSON for frontend visualization

    Parameters
    ----------
    timeout:
        Overall timeout for the scan operation in seconds.
    ports:
        Port specification (default "1-1024", use "-" for all ports).
    debug:
        If 1, includes raw ARP and nmap data in response for troubleshooting.

    Returns
    -------
    Topology JSON with nodes and edges, optionally including debug data.
    """
    debug_mode = debug == 1
    debug_data: Dict[str, Any] = {}
    steps: List[Dict[str, Any]] = []

    def add_step(stage: str, message: str, **extras: Any) -> None:
        payload: Dict[str, Any] = {"stage": stage, "message": message}
        if extras:
            payload.update(extras)
        steps.append(payload)
        logger.info(f"[{stage}] {message}")

    try:
        interface, gateway_ip, network = _resolve_primary_interface()
        add_step(
            "interface",
            "Primary interface resolved",
            interface=interface,
            gateway=gateway_ip,
            network=str(network) if network else None,
        )
    except Exception as exc:
        logger.error(f"Interface detection failed: {exc}")
        add_step("error", "Interface detection failed", error=str(exc))
        if debug_mode:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return FALLBACK_TOPOLOGY

    # Step 1: ARP discovery (non-blocking via executor)
    def _arp_discovery() -> Dict[str, Any]:
        return discover_devices(
            interface,
            network,
            sweep_timeout=min(timeout * 0.1, 3.0),
            sniff_timeout=min(timeout * 0.2, 8),
            retry=1,
            verbose=debug_mode,
        )

    try:
        add_step("arp", "Starting ARP discovery")
        arp_result = await run_in_threadpool(_arp_discovery)
        arp_map = arp_result.get("hosts", {})
        method = arp_result.get("method", "unknown")
        logger.info(f"ARP discovery ({method}) found {len(arp_map)} devices")
        add_step("arp", "ARP discovery completed", method=method, device_count=len(arp_map))
        if debug_mode:
            debug_data["arp_discovery"] = arp_result
    except Exception as exc:
        logger.warning(f"ARP discovery failed: {exc}")
        add_step("arp", "ARP discovery failed", error=str(exc))
        arp_map = {}
        if debug_mode:
            debug_data["arp_error"] = str(exc)

    # Step 2: Build target list for nmap
    target_hosts: List[str] = sorted(set(ip for ip in arp_map.keys() if ip))
    add_step("targets", "Initial targets from ARP", targets=target_hosts)
    if gateway_ip and gateway_ip not in target_hosts:
        target_hosts.append(gateway_ip)

    # Fallback: if ARP found nothing, try nmap host discovery
    if not target_hosts and network:
        logger.info("ARP found no hosts, trying nmap host discovery")
        add_step("host_discovery", "ARP found no hosts, trying nmap host discovery")
        try:

            def _quick_discovery() -> List[str]:
                return quick_host_discovery([str(network)], timeout=min(timeout // 4, 10))

            target_hosts = await run_in_threadpool(_quick_discovery)
            if debug_mode:
                debug_data["nmap_host_discovery"] = target_hosts
            add_step("host_discovery", "Nmap host discovery completed", targets=target_hosts)
        except Exception as exc:
            logger.warning(f"Host discovery failed: {exc}")
            add_step("host_discovery", "Nmap host discovery failed", error=str(exc))
            if debug_mode:
                debug_data["host_discovery_error"] = str(exc)

    # Last resort: scan whole subnet
    if not target_hosts and network:
        target_hosts = [str(network)]
        logger.info(f"Falling back to subnet scan: {network}")
        add_step("targets", "Falling back to subnet scan", subnet=str(network))

    # Step 3: Nmap port/service scan (non-blocking, batched, parallelized)
    nmap_steps: List[str] = []

    def _nmap_scan() -> Dict[str, Dict[str, Any]]:
        return scan_hosts(
            target_hosts,
            ports=ports,
            timing=DEFAULT_TIMING,
            min_rate=DEFAULT_MIN_RATE,
            host_timeout=DEFAULT_HOST_TIMEOUT,
            service_version=True,
            batch_size=DEFAULT_BATCH_SIZE,
            max_workers=DEFAULT_MAX_WORKERS,
            global_timeout=timeout,
            log_steps=nmap_steps,
        )

    try:
        add_step(
            "nmap",
            "Starting Nmap scan",
            targets=target_hosts,
            ports=ports,
            timing=DEFAULT_TIMING,
            min_rate=DEFAULT_MIN_RATE,
        )
        nmap_results = await run_in_threadpool(_nmap_scan)
        logger.info(f"Nmap scan completed for {len(nmap_results)} hosts")
        add_step("nmap", "Nmap scan completed", host_count=len(nmap_results))
        if debug_mode:
            debug_data["nmap_results"] = nmap_results
            debug_data["nmap_steps"] = nmap_steps
    except Exception as exc:
        logger.error(f"Nmap scan failed: {exc}")
        add_step("nmap", "Nmap scan failed", error=str(exc))
        nmap_results = {}
        if debug_mode:
            debug_data["nmap_error"] = str(exc)

    # Step 4: Correlate and build topology
    if not arp_map and not nmap_results:
        logger.warning("No devices discovered, returning fallback data")
        add_step("topology", "No devices discovered, returning fallback topology")
        result = FALLBACK_TOPOLOGY.copy()
        if debug_mode:
            result["debug"] = debug_data
        return result

    nodes: Dict[str, Dict[str, Any]] = {}
    all_hosts = sorted(set(list(arp_map.keys()) + list(nmap_results.keys())))

    for ip in all_hosts:
        nmap_entry = nmap_results.get(ip, {})
        hostname = nmap_entry.get("hostname") or ""
        ports_list = nmap_entry.get("ports") or []
        # Prefer MAC from nmap (more reliable), fall back to ARP
        mac = nmap_entry.get("mac") or arp_map.get(ip) or ""
        node_type = _infer_device_type(hostname, ports_list)
        label = hostname or ip

        nodes[ip] = {
            "id": ip,
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "label": label,
            "type": node_type,
            "ports": ports_list,
        }

    result = {
        "nodes": list(nodes.values()),
        "edges": _build_edges(nodes, gateway_ip),
    }

    if debug_mode:
        debug_data["steps"] = steps
        result["debug"] = debug_data

    logger.info(f"Topology built: {len(nodes)} nodes, {len(result['edges'])} edges")
    add_step("topology", "Topology built", node_count=len(nodes), edge_count=len(result["edges"]))
    return result


# --------------------------------------------------------------------------- #
# Frontend serving (Vite production build) - mounted AFTER API routes
# --------------------------------------------------------------------------- #


@app.get("/", response_class=HTMLResponse)
async def serve_index() -> HTMLResponse:
    """Serve the SPA entry point."""
    index_path = FRONTEND_DIST / "index.html"
    if not index_path.exists():
        raise HTTPException(
            status_code=500,
            detail="Frontend build missing. Run `npm install && npm run build` in frontend/.",
        )
    return HTMLResponse(index_path.read_text(encoding="utf-8"))


assets_dir = FRONTEND_DIST / "assets"
if assets_dir.exists():
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")


@app.get("/{resource_path:path}")
async def serve_static(resource_path: str) -> FileResponse:
    """Serve remaining static resources with SPA fallback."""
    candidate = FRONTEND_DIST / resource_path
    if candidate.is_file():
        return FileResponse(candidate)

    index_path = FRONTEND_DIST / "index.html"
    if index_path.exists():
        return FileResponse(index_path)

    raise HTTPException(status_code=404, detail=f"Asset '{resource_path}' not found.")
