"""
ARP discovery module with multiple fallback methods.

This module attempts discovery in order:
1. Scapy ARP sweep (srp) - active probing
2. Scapy passive sniffing - capture existing ARP traffic
3. Nmap ping-sweep (-sn) - host discovery fallback
4. System ARP table parsing (ip neigh / arp -n) - last resort

All methods are wrapped in try/except to handle Scapy socket errors gracefully.
The L2ListenSocket error typically occurs when Scapy can't bind to the interface
or when comparing NoneType values in socket operations. We catch these and fall
back to alternative methods.

PERMISSIONS:
-----------
For Scapy methods, elevated privileges are required:
- sudo python -m uvicorn backend.main:app --reload
- OR: sudo setcap cap_net_raw,cap_net_admin+eip /path/to/venv/bin/python3

For nmap and ARP table parsing, sudo is also recommended but not always required.

"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import threading
import warnings
from typing import Dict, Optional

try:
    from scapy.all import ARP, AsyncSniffer, Ether, conf, get_if_hwaddr, srp  # type: ignore[import]
    from scapy.error import Scapy_Exception  # type: ignore[import]

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Scapy_Exception = Exception


def _parse_arp_table() -> Dict[str, str]:
    """
    Parse system ARP table using 'ip neigh' (preferred) or 'arp -n' (fallback).

    Returns IP -> MAC mapping from the kernel's ARP cache.
    """
    results: Dict[str, str] = {}

    # Try 'ip neigh' first (modern Linux)
    try:
        proc = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[3] == "lladdr":
                    ip = parts[0]
                    mac = parts[4].lower()
                    if ip and mac and mac != "00:00:00:00:00:00":
                        results[ip] = mac
            return results
    except Exception:
        pass

    # Fallback to 'arp -n' (older systems)
    try:
        proc = subprocess.run(
            ["arp", "-n"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0:
            # Parse arp -n output: "192.168.1.1 ether aa:bb:cc:dd:ee:ff ..."
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+ether\s+([0-9a-fA-F:]{17})"
            for match in re.finditer(pattern, proc.stdout):
                ip = match.group(1)
                mac = match.group(2).lower()
                if mac != "00:00:00:00:00:00":
                    results[ip] = mac
    except Exception:
        pass

    return results


def _nmap_ping_sweep(network: ipaddress.IPv4Network, timeout: int = 10) -> Dict[str, str]:
    """
    Use nmap ping-sweep (-sn) to discover hosts, then query ARP table for MACs.

    This is a reliable fallback when Scapy fails.
    """
    results: Dict[str, str] = {}
    try:
        proc = subprocess.run(
            ["nmap", "-sn", str(network)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            # Extract IPs from nmap output
            ip_pattern = r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)"
            discovered_ips = re.findall(ip_pattern, proc.stdout)

            # Get MACs from ARP table for discovered IPs
            arp_table = _parse_arp_table()
            for ip in discovered_ips:
                if ip in arp_table:
                    results[ip] = arp_table[ip]
                else:
                    # Include IP even without MAC
                    results[ip] = ""
    except Exception:
        pass

    return results


def _scapy_arp_sweep(
    interface: str,
    network: ipaddress.IPv4Network,
    *,
    timeout: float = 2.0,
    retry: int = 1,
) -> Dict[str, str]:
    """
    Perform ARP sweep using Scapy srp with explicit error handling.

    Catches Scapy socket errors (including L2ListenSocket comparison errors)
    and returns empty dict on failure.
    """
    if not SCAPY_AVAILABLE:
        return {}

    results: Dict[str, str] = {}

    try:
        # Explicitly set interface in Scapy config to avoid socket binding issues
        conf.iface = interface

        # Get our MAC address
        our_mac = get_if_hwaddr(interface)
        if not our_mac or our_mac == "00:00:00:00:00:00":
            return {}

        # Build target IP list
        target_ips = [str(ip) for ip in network.hosts()]

        # Suppress Scapy warnings about socket operations
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            # Create ARP request packet
            arp_request = ARP(pdst=target_ips)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff", src=our_mac)
            packet = ether / arp_request

            # Send and receive with explicit timeout and retry
            answered, _ = srp(
                packet,
                iface=interface,
                timeout=timeout,
                verbose=False,
                retry=retry,
            )

            for sent, received in answered:
                if received and received.haslayer(ARP):
                    arp_layer = received[ARP]
                    ip = getattr(arp_layer, "psrc", None)
                    mac = getattr(arp_layer, "hwsrc", None)
                    if ip and mac:
                        results[str(ip)] = str(mac).lower()

    except (Scapy_Exception, OSError, ValueError, TypeError, AttributeError) as exc:
        # Catch Scapy socket errors, comparison errors (NoneType), and other issues
        # Return empty to trigger fallback
        pass
    except Exception:
        # Catch any other unexpected errors
        pass

    return results


def _scapy_arp_sniff(
    interface: str,
    *,
    timeout: int = 5,
    packet_count: Optional[int] = None,
) -> Dict[str, str]:
    """
    Passively sniff ARP packets with explicit error handling.

    Catches Scapy socket binding errors gracefully.
    """
    if not SCAPY_AVAILABLE:
        return {}

    results: Dict[str, str] = {}
    lock = threading.Lock()

    def _record(packet) -> None:
        try:
            if packet and packet.haslayer(ARP):
                arp_layer = packet[ARP]
                ip = getattr(arp_layer, "psrc", None)
                mac = getattr(arp_layer, "hwsrc", None)
                if ip and mac:
                    with lock:
                        results[str(ip)] = str(mac).lower()
        except Exception:
            pass

    try:
        # Explicitly set interface
        conf.iface = interface

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            sniffer = AsyncSniffer(
                iface=interface,
                filter="arp",
                prn=_record,
                store=False,
                count=packet_count,
            )
            sniffer.start()
            sniffer.join(timeout=timeout)
            if sniffer.running:
                sniffer.stop()

    except (Scapy_Exception, OSError, ValueError, TypeError, AttributeError):
        # Catch Scapy errors silently
        pass
    except Exception:
        pass

    return results


def discover_devices(
    interface: str,
    network: ipaddress.IPv4Network,
    *,
    sweep_timeout: float = 2.0,
    sniff_timeout: int = 5,
    retry: int = 1,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Multi-method ARP discovery with automatic fallbacks.

    Attempts methods in order until one succeeds or all fail.
    Returns structured result with method used and raw debug info.

    Parameters
    ----------
    interface:
        Network interface name.
    network:
        IPv4Network object.
    sweep_timeout:
        Timeout for ARP sweep in seconds.
    sniff_timeout:
        Timeout for passive sniffing in seconds.
    retry:
        Number of retries for ARP sweep.
    verbose:
        Include raw debug information in result.

    Returns
    -------
    Dictionary with keys:
    - interface: Interface name used
    - subnet: Subnet string
    - hosts: IP -> MAC mapping
    - method: Discovery method used ("scapy-srp", "scapy-sniff", "nmap-ping", "arp-table")
    - raw: Optional debug information
    """
    result: Dict[str, Any] = {
        "interface": interface,
        "subnet": str(network),
        "hosts": {},
        "method": "none",
        "raw": None,
    }

    # Method 1: Scapy ARP sweep
    if SCAPY_AVAILABLE:
        try:
            sweep_results = _scapy_arp_sweep(
                interface, network, timeout=sweep_timeout, retry=retry
            )
            if sweep_results:
                result["hosts"] = sweep_results
                result["method"] = "scapy-srp"
                if verbose:
                    result["raw"] = f"Scapy ARP sweep found {len(sweep_results)} hosts"
                return result
        except Exception:
            pass

        # Method 2: Scapy passive sniffing
        try:
            sniff_results = _scapy_arp_sniff(interface, timeout=sniff_timeout)
            if sniff_results:
                result["hosts"].update(sniff_results)
                result["method"] = "scapy-sniff"
                if verbose:
                    result["raw"] = f"Scapy sniff found {len(sniff_results)} hosts"
                if result["hosts"]:
                    return result
        except Exception:
            pass

    # Method 3: Nmap ping-sweep + ARP table
    try:
        nmap_results = _nmap_ping_sweep(network, timeout=10)
        if nmap_results:
            result["hosts"] = nmap_results
            result["method"] = "nmap-ping"
            if verbose:
                result["raw"] = f"Nmap ping-sweep found {len(nmap_results)} hosts"
            return result
    except Exception:
        pass

    # Method 4: ARP table only (last resort)
    try:
        arp_table = _parse_arp_table()
        if arp_table:
            result["hosts"] = arp_table
            result["method"] = "arp-table"
            if verbose:
                result["raw"] = f"ARP table contained {len(arp_table)} entries"
            return result
    except Exception:
        pass

    # All methods failed
    result["method"] = "failed"
    if verbose:
        result["raw"] = "All discovery methods failed"
    return result


__all__ = ["discover_devices"]
