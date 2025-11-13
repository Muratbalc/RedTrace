"""
Nmap-based port and service discovery module with XML parsing and batching.

This module uses subprocess to execute nmap with XML output (-oX -) for reliable
parsing. It supports batching, parallelization, and automatic privilege detection
with fallback to unprivileged scans.

PERMISSIONS:
-----------
Privileged scans (SYN -sS) are faster and more reliable. Options:
- sudo python -m uvicorn backend.main:app --reload
- OR: sudo setcap cap_net_raw,cap_net_admin+eip /path/to/venv/bin/python3

Without privileges, automatically falls back to TCP connect scans (-sT).
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List, Optional, Tuple

PortInfo = Dict[str, str]
HostScanResult = Dict[str, object]


def _normalize_timing(timing: str) -> str:
    """Return a valid nmap -T argument from various user inputs.

    Accepts numeric levels ("0"-"5"), names ("Paranoid"-"Insane"), or
    common forms like "T4". Falls back to "4" (Aggressive) on invalid input.
    """

    if not timing:
        return "4"

    value = str(timing).strip()

    # Strip leading "-T" or "T" if present (e.g. "-T4", "T4")
    if value.lower().startswith("-t"):
        value = value[2:]
    elif value.lower().startswith("t"):
        value = value[1:]

    value = value.strip()

    # Named templates allowed by nmap
    named_templates = {
        "paranoid": "Paranoid",
        "sneaky": "Sneaky",
        "polite": "Polite",
        "normal": "Normal",
        "aggressive": "Aggressive",
        "insane": "Insane",
    }

    lower = value.lower()
    if lower in named_templates:
        return named_templates[lower]

    # Numeric levels 0-5
    if value.isdigit():
        num = int(value)
        if 0 <= num <= 5:
            return str(num)

    # Fallback to a safe aggressive scan
    return "4"


def _is_privileged() -> bool:
    """Check if process has privileges for raw socket operations."""
    return os.geteuid() == 0


def _build_nmap_command(
    hosts: List[str],
    *,
    ports: str = "-",
    timing: str = "T4",
    min_rate: int = 100,
    host_timeout: int = 30,
    service_version: bool = True,
) -> List[str]:
    """
    Build nmap command with appropriate scan type based on privileges.

    Parameters
    ----------
    hosts:
        List of target IP addresses.
    ports:
        Port specification (default "-" for all ports, or "1-1024", "22,80,443", etc.).
    timing:
        Timing template (T0-T5, default T4). Accepts forms like "4", "T4",
        or names like "Aggressive".
    min_rate:
        Minimum packets per second.
    host_timeout:
        Per-host timeout in seconds.
    service_version:
        Enable service version detection (-sV).

    Returns
    -------
    List of command arguments for subprocess.
    """
    cmd = ["nmap"]

    # Select scan type based on privileges
    if _is_privileged():
        cmd.extend(["-sS"])  # SYN scan
    else:
        cmd.extend(["-sT"])  # TCP connect scan

    if service_version:
        cmd.append("-sV")

    normalized_timing = _normalize_timing(timing)

    cmd.extend(["-p", ports])
    cmd.extend(["-T", normalized_timing])
    cmd.extend(["--min-rate", str(min_rate)])
    cmd.extend(["--host-timeout", f"{host_timeout}s"])
    cmd.append("-oX")  # XML output
    cmd.append("-")  # stdout

    # Add targets
    cmd.extend(hosts)

    return cmd


def _parse_nmap_xml(xml_output: str) -> Dict[str, HostScanResult]:
    """
    Parse nmap XML output and extract port information.

    Parameters
    ----------
    xml_output:
        XML string from nmap -oX -.

    Returns
    -------
    Dictionary mapping IP addresses to scan results.
    """
    results: Dict[str, HostScanResult] = {}

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        return results

    for host in root.findall("host"):
        # Extract IP address
        address_elem = host.find("address[@addrtype='ipv4']")
        if address_elem is None:
            continue
        ip = address_elem.get("addr")
        if not ip:
            continue

        # Extract MAC address
        mac = None
        mac_elem = host.find("address[@addrtype='mac']")
        if mac_elem is not None:
            mac = mac_elem.get("addr", "").lower()

        # Extract hostname
        hostname = ""
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            hostname_elem = hostnames_elem.find("hostname")
            if hostname_elem is not None:
                hostname = hostname_elem.get("name", "")

        # Extract ports
        ports: List[PortInfo] = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_num = port_elem.get("portid")
                if not port_num:
                    continue

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service = ""
                version = ""

                if service_elem is not None:
                    service = service_elem.get("name", "") or service_elem.get("product", "")
                    version_parts = [
                        service_elem.get("product", ""),
                        service_elem.get("version", ""),
                        service_elem.get("extrainfo", ""),
                    ]
                    version = " ".join(filter(None, version_parts)).strip()

                ports.append(
                    {
                        "port": int(port_num),
                        "state": state,
                        "service": service,
                        "version": version,
                    }
                )

        results[ip] = {
            "mac": mac,
            "hostname": hostname,
            "ports": sorted(ports, key=lambda item: item["port"]),
        }

    return results


def _scan_batch(
    hosts: List[str],
    *,
    ports: str = "-",
    timing: str = "T4",
    min_rate: int = 100,
    host_timeout: int = 30,
    service_version: bool = True,
    global_timeout: Optional[int] = None,
) -> Tuple[Dict[str, HostScanResult], Optional[str]]:
    """
    Scan a single batch of hosts using nmap subprocess.

    Parameters
    ----------
    hosts:
        List of target IP addresses.
    ports:
        Port specification.
    timing:
        Timing template.
    min_rate:
        Minimum packets per second.
    host_timeout:
        Per-host timeout in seconds.
    service_version:
        Enable service version detection.
    global_timeout:
        Overall timeout for the batch in seconds.

    Returns
    -------
    Tuple of (results dictionary, error message if any).
    """
    if not hosts:
        return {}, None

    cmd = _build_nmap_command(
        hosts,
        ports=ports,
        timing=timing,
        min_rate=min_rate,
        host_timeout=host_timeout,
        service_version=service_version,
    )

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=global_timeout,
            check=False,
        )

        if proc.returncode != 0:
            error_msg = proc.stderr or f"nmap exited with code {proc.returncode}"
            # Try to parse partial results even on error
            if proc.stdout:
                results = _parse_nmap_xml(proc.stdout)
                if results:
                    return results, error_msg
            return {}, error_msg

        results = _parse_nmap_xml(proc.stdout)
        return results, None

    except subprocess.TimeoutExpired:
        return {}, "Scan batch timed out"
    except FileNotFoundError:
        return {}, "nmap command not found. Install with: sudo apt install nmap"
    except Exception as exc:
        return {}, f"Scan error: {str(exc)}"


def scan_hosts(
    hosts: Iterable[str],
    *,
    ports: str = "-",
    timing: str = "T4",
    min_rate: int = 100,
    host_timeout: int = 30,
    service_version: bool = True,
    batch_size: int = 50,
    max_workers: int = 4,
    global_timeout: Optional[int] = None,
    log_steps: Optional[List[str]] = None,
) -> Dict[str, HostScanResult]:
    """
    Scan multiple hosts with batching and parallelization.

    Parameters
    ----------
    hosts:
        Iterable of target IPv4 addresses.
    ports:
        Port specification (default "-" for all ports).
        Examples: "1-1024", "22,80,443", "80-443".
    timing:
        Timing template T0-T5 (default T4 = aggressive).
    min_rate:
        Minimum packets per second (default 100).
    host_timeout:
        Per-host timeout in seconds (default 30).
    service_version:
        Enable service version detection (default True).
    batch_size:
        Number of hosts per batch (default 50).
    max_workers:
        Maximum concurrent batches (default 4).
    global_timeout:
        Overall timeout for all batches in seconds (optional).

    Returns
    -------
    Dictionary mapping IP addresses to scan results:
    - mac: MAC address (if available)
    - hostname: Resolved hostname
    - ports: List of port info dicts [{"port": 22, "state": "open", "service": "ssh", "version": "..."}]
    """
    targets = sorted({host for host in hosts if host})
    if not targets:
        return {}

    logger = logging.getLogger(__name__)

    if log_steps is not None:
        log_steps.append(
            f"Starting Nmap scan for {len(targets)} targets "
            f"(ports={ports}, timing={timing}, batch_size={batch_size}, max_workers={max_workers})"
        )

    # Split into batches
    batches: List[List[str]] = []
    for i in range(0, len(targets), batch_size):
        batches.append(targets[i : i + batch_size])

    all_results: Dict[str, HostScanResult] = {}
    errors: List[str] = []

    # Scan batches in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_batch = {
            executor.submit(
                _scan_batch,
                batch,
                ports=ports,
                timing=timing,
                min_rate=min_rate,
                host_timeout=host_timeout,
                service_version=service_version,
                global_timeout=global_timeout,
            ): batch
            for batch in batches
        }

        for future in concurrent.futures.as_completed(future_to_batch):
            batch = future_to_batch[future]
            try:
                results, error = future.result()
                all_results.update(results)
                if error:
                    errors.append(f"Batch {batch[0]}-{batch[-1]}: {error}")
                    if log_steps is not None:
                        log_steps.append(f"Batch {batch[0]}-{batch[-1]} failed: {error}")
                else:
                    if log_steps is not None:
                        log_steps.append(
                            f"Batch {batch[0]}-{batch[-1]} completed: {len(results)} hosts scanned"
                        )
            except Exception as exc:
                errors.append(f"Batch {batch[0]}-{batch[-1]}: {str(exc)}")
                if log_steps is not None:
                    log_steps.append(f"Batch {batch[0]}-{batch[-1]} raised exception: {exc}")

    if errors:
        # Log errors but return partial results
        logger.warning(f"Scan completed with {len(errors)} errors: {errors[:3]}")

    return all_results


def quick_host_discovery(hosts: Iterable[str], *, timeout: int = 5) -> List[str]:
    """
    Quick host discovery using nmap ping scan (-sn).

    Parameters
    ----------
    hosts:
        Iterable of target IPv4 addresses or CIDR subnets.
    timeout:
        Per-host timeout in seconds.

    Returns
    -------
    List of IP addresses that responded to discovery probes.
    """
    targets = sorted({host for host in hosts if host})
    if not targets:
        return []

    cmd = ["nmap", "-sn", "--host-timeout", f"{timeout}s", "-oX", "-"] + targets

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * len(targets))
        if proc.returncode != 0:
            return []

        root = ET.fromstring(proc.stdout)
        discovered = []
        for host in root.findall("host"):
            address_elem = host.find("address[@addrtype='ipv4']")
            if address_elem is not None:
                ip = address_elem.get("addr")
                if ip:
                    discovered.append(ip)
        return discovered

    except Exception:
        return []


__all__ = ["scan_hosts", "quick_host_discovery"]
