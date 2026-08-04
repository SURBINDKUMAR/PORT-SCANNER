"""
port_scanner.py
----------------
Core scanning engine for the Advanced Port Scanner.

Implements:
    - Multi-threaded TCP Connect scanning
    - Optional SYN scanning (requires the 'scapy' library + admin/root
      privileges). Falls back gracefully to TCP Connect scan if scapy
      is unavailable or privileges are insufficient.
    - Common port list and arbitrary port range parsing
    - Timeout handling, logging, and real-time progress callbacks

LEGAL / ETHICAL NOTICE
-----------------------
This tool must ONLY be used against systems you own or have explicit,
documented authorization to test (e.g., your own lab, a CTF range, or
a system covered by a signed penetration-testing agreement). Scanning
systems without authorization may be illegal in your jurisdiction.
"""

import socket
import time
import logging
import threading
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, List, Optional

from scanner.service_detection import (
    get_service_name,
    grab_banner,
    guess_version_from_banner,
    get_security_note,
)

# Try to import scapy for optional SYN scanning. This is optional -
# the tool works fully without it (falls back to TCP Connect scan).
try:
    from scapy.all import sr1, IP, TCP  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# The 20 most commonly checked ports - used for "quick scan" mode.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1433, 3306, 3389, 5900, 8080,
]

logger = logging.getLogger("AdvancedPortScanner")


@dataclass
class PortResult:
    """Represents the scan result for a single port."""
    port: int
    state: str                # OPEN / CLOSED / FILTERED
    service: str = "unknown"
    version: str = "Unknown"
    banner: str = ""
    security_note: str = ""


@dataclass
class ScanSummary:
    """Aggregated results and metadata for a completed/partial scan."""
    target: str = ""
    resolved_ip: str = ""
    scan_type: str = "TCP Connect"
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    total_ports_scanned: int = 0
    open_ports: List[PortResult] = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0
    all_results: List[PortResult] = field(default_factory=list)


def parse_port_input(port_input: str) -> List[int]:
    """
    Parse a user-provided port specification into a sorted list of
    unique port integers.

    Supports:
        - Single ports:      "80"
        - Comma lists:       "22,80,443"
        - Ranges:             "1-1024"
        - Mixed:              "22,80,1000-1010"
        - Keyword "common":   returns COMMON_PORTS

    Args:
        port_input: Raw string from the UI/CLI.

    Returns:
        Sorted list of valid port numbers (1-65535).

    Raises:
        ValueError: If the input cannot be parsed into valid ports.
    """
    port_input = port_input.strip().lower()

    if port_input in ("common", "", "default"):
        return sorted(COMMON_PORTS)

    ports = set()
    chunks = [c.strip() for c in port_input.split(",") if c.strip()]

    if not chunks:
        raise ValueError("No ports specified.")

    for chunk in chunks:
        if "-" in chunk:
            start_str, end_str = chunk.split("-", 1)
            start, end = int(start_str), int(end_str)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    valid_ports = sorted(p for p in ports if 1 <= p <= 65535)
    if not valid_ports:
        raise ValueError("No valid ports (1-65535) found in input.")
    return valid_ports


class PortScanner:
    """
    Multi-threaded port scanner supporting TCP Connect and (optional)
    SYN scanning, with live progress callbacks and cooperative
    stop/cancel support.
    """

    def __init__(
        self,
        max_threads: int = 100,
        timeout: float = 1.0,
        detect_services: bool = True,
    ):
        """
        Args:
            max_threads: Maximum concurrent worker threads.
            timeout: Per-connection timeout in seconds.
            detect_services: Whether to grab banners / guess versions
                for open ports (slightly slower, more informative).
        """
        self.max_threads = max_threads
        self.timeout = timeout
        self.detect_services = detect_services
        self._stop_event = threading.Event()

    def stop(self):
        """Signal all in-flight and pending scan tasks to stop early."""
        self._stop_event.set()

    def reset(self):
        """Clear the stop flag so the scanner instance can be reused."""
        self._stop_event.clear()

    # ------------------------------------------------------------------
    # TCP Connect scan (default, works everywhere, no special privileges)
    # ------------------------------------------------------------------
    def _tcp_connect_scan_port(self, ip: str, port: int) -> PortResult:
        """
        Attempt a full TCP three-way handshake against a single port.

        Returns:
            PortResult describing the outcome (OPEN/CLOSED/FILTERED).
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            result_code = sock.connect_ex((ip, port))
            if result_code == 0:
                state = "OPEN"
            else:
                state = "CLOSED"
        except socket.timeout:
            state = "FILTERED"
        except OSError:
            state = "FILTERED"
        finally:
            sock.close()

        service = get_service_name(port)
        banner, version, note = "", "Unknown", ""

        if state == "OPEN" and self.detect_services:
            banner = grab_banner(ip, port, timeout=min(self.timeout, 1.5))
            version = guess_version_from_banner(banner)
            note = get_security_note(service)

        return PortResult(
            port=port,
            state=state,
            service=service,
            version=version,
            banner=banner,
            security_note=note,
        )

    # ------------------------------------------------------------------
    # SYN scan (optional - requires scapy + root/admin privileges)
    # ------------------------------------------------------------------
    def _syn_scan_port(self, ip: str, port: int) -> PortResult:
        """
        Attempt a SYN (half-open) scan against a single port using scapy.
        Requires root/admin privileges and the scapy library.

        Falls back to a TCP connect scan for this port if scapy is not
        available or the raw packet cannot be sent (e.g., insufficient
        privileges).

        Returns:
            PortResult describing the outcome.
        """
        if not SCAPY_AVAILABLE:
            return self._tcp_connect_scan_port(ip, port)

        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            response = sr1(pkt, timeout=self.timeout, verbose=0)

            if response is None:
                state = "FILTERED"
            elif response.haslayer(TCP):
                flags = response.getlayer(TCP).flags
                if flags == 0x12:  # SYN-ACK
                    state = "OPEN"
                    # Politely close the half-open connection
                    rst_pkt = IP(dst=ip) / TCP(dport=port, flags="R")
                    sr1(rst_pkt, timeout=self.timeout, verbose=0)
                elif flags == 0x14:  # RST-ACK
                    state = "CLOSED"
                else:
                    state = "FILTERED"
            else:
                state = "FILTERED"
        except PermissionError:
            logger.warning("Insufficient privileges for SYN scan; "
                            "falling back to TCP connect scan.")
            return self._tcp_connect_scan_port(ip, port)
        except Exception as exc:
            logger.warning(f"SYN scan error on port {port}: {exc}. "
                            "Falling back to TCP connect scan.")
            return self._tcp_connect_scan_port(ip, port)

        service = get_service_name(port)
        banner, version, note = "", "Unknown", ""

        if state == "OPEN" and self.detect_services:
            banner = grab_banner(ip, port, timeout=min(self.timeout, 1.5))
            version = guess_version_from_banner(banner)
            note = get_security_note(service)

        return PortResult(
            port=port, state=state, service=service,
            version=version, banner=banner, security_note=note,
        )

    # ------------------------------------------------------------------
    # Main scan orchestration
    # ------------------------------------------------------------------
    def scan(
        self,
        ip: str,
        ports: List[int],
        scan_type: str = "TCP Connect",
        progress_callback: Optional[Callable[[PortResult, int, int], None]] = None,
    ) -> ScanSummary:
        """
        Run a multi-threaded scan of the given ports against the target.

        Args:
            ip: Resolved target IP address.
            ports: List of port numbers to scan.
            scan_type: "TCP Connect" or "SYN".
            progress_callback: Optional callable invoked after each port
                is scanned, receiving (PortResult, completed_count, total).

        Returns:
            ScanSummary with all results and aggregate statistics.
        """
        self.reset()
        summary = ScanSummary(
            target=ip,
            resolved_ip=ip,
            scan_type=scan_type,
            start_time=time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        start_perf = time.perf_counter()

        scan_func = (
            self._syn_scan_port if scan_type.upper().startswith("SYN")
            else self._tcp_connect_scan_port
        )

        completed = 0
        total = len(ports)

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(scan_func, ip, port): port for port in ports
            }

            for future in as_completed(future_to_port):
                if self._stop_event.is_set():
                    logger.info("Scan stopped by user request.")
                    break

                port = future_to_port[future]
                try:
                    result = future.result()
                except Exception as exc:
                    logger.error(f"Error scanning port {port}: {exc}")
                    result = PortResult(port=port, state="ERROR")

                completed += 1
                summary.all_results.append(result)

                if result.state == "OPEN":
                    summary.open_ports.append(result)
                elif result.state == "CLOSED":
                    summary.closed_count += 1
                elif result.state == "FILTERED":
                    summary.filtered_count += 1

                if progress_callback:
                    progress_callback(result, completed, total)

        summary.total_ports_scanned = completed
        summary.end_time = time.strftime("%Y-%m-%d %H:%M:%S")
        summary.duration_seconds = round(time.perf_counter() - start_perf, 2)
        summary.all_results.sort(key=lambda r: r.port)
        summary.open_ports.sort(key=lambda r: r.port)

        return summary
