"""
network_info.py
----------------
Helper functions for resolving targets, gathering basic target
information, and (very) basic OS fingerprinting based on TTL values.

NOTE: This module is for EDUCATIONAL and AUTHORIZED testing only.
It does not perform any intrusive or illegal network activity.
"""

import socket
import struct
import time
import platform
import subprocess


def resolve_target(target: str) -> str:
    """
    Resolve a hostname to an IPv4 address.
    If the target is already an IP address, it is returned unchanged.

    Args:
        target: Hostname or IP address string.

    Returns:
        Resolved IPv4 address as a string.

    Raises:
        socket.gaierror: If the hostname cannot be resolved.
    """
    try:
        # This works whether target is a hostname or already an IP
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise socket.gaierror(f"Could not resolve target '{target}': {exc}")


def get_target_info(target: str) -> dict:
    """
    Gather basic information about the scan target.

    Args:
        target: Hostname or IP address.

    Returns:
        Dictionary with resolved IP, hostname (if available), and timestamp.
    """
    info = {
        "input_target": target,
        "resolved_ip": None,
        "hostname": None,
        "scan_start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    try:
        info["resolved_ip"] = resolve_target(target)
    except socket.gaierror:
        info["resolved_ip"] = "Unresolved"
        return info

    try:
        # Reverse lookup - best effort, may fail silently
        hostname, _, _ = socket.gethostbyaddr(info["resolved_ip"])
        info["hostname"] = hostname
    except (socket.herror, socket.gaierror):
        info["hostname"] = "N/A"

    return info


def ping_ttl(target_ip: str, timeout: int = 2) -> int:
    """
    Perform a single OS-native ping and attempt to extract the TTL value.
    Used only for basic OS fingerprinting (see guess_os_from_ttl).

    This uses the system 'ping' utility (cross-platform) rather than
    raw sockets, so it works without elevated privileges in most cases.

    Args:
        target_ip: IP address to ping.
        timeout: Timeout in seconds for the ping command.

    Returns:
        TTL value as an integer, or -1 if it could not be determined.
    """
    system = platform.system().lower()

    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), target_ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), target_ip]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 2
        )
        output = result.stdout.lower()

        for line in output.splitlines():
            if "ttl=" in line:
                # Extract number after ttl=
                part = line.split("ttl=")[1]
                ttl_str = "".join(ch for ch in part if ch.isdigit())
                if ttl_str:
                    return int(ttl_str)
    except Exception:
        pass

    return -1


def guess_os_from_ttl(ttl: int) -> str:
    """
    Very basic OS fingerprinting heuristic based on common default TTL
    values. This is NOT a reliable OS detection technique - real tools
    (e.g., Nmap) use much more sophisticated stack fingerprinting.

    Args:
        ttl: TTL value obtained from a ping reply.

    Returns:
        A best-guess OS family string.
    """
    if ttl <= 0:
        return "Unknown (no ICMP reply)"
    if ttl <= 64:
        return "Likely Linux/Unix/macOS (TTL <= 64)"
    if ttl <= 128:
        return "Likely Windows (TTL <= 128)"
    return "Likely Network Device/Solaris (TTL > 128)"
