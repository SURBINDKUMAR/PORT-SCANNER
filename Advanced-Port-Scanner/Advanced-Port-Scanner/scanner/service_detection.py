"""
service_detection.py
---------------------
Service name lookup, banner grabbing, and lightweight version parsing.

Also provides generic, non-exploitative security advisory text for
commonly-known service categories. This module intentionally does NOT
contain any exploit code or attack payloads - it only offers general
best-practice hardening reminders for educational purposes.
"""

import socket

# A small, well-known port -> service map used as a fallback when the
# OS-level services database doesn't have an entry (e.g., on some
# minimal systems) or for quick, consistent labeling in reports.
COMMON_SERVICES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBIND", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NETBIOS-NS", 138: "NETBIOS-DGM", 139: "NETBIOS-SSN",
    143: "IMAP", 161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "SYSLOG", 587: "SMTP-SUBMISSION",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "ORACLE-DB", 2049: "NFS",
    2375: "DOCKER", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL",
    5900: "VNC", 5985: "WINRM-HTTP", 6379: "REDIS", 8080: "HTTP-ALT",
    8443: "HTTPS-ALT", 9200: "ELASTICSEARCH", 27017: "MONGODB",
}

# Generic, non-exploit hardening reminders keyed by service name.
# These are intentionally high-level (defensive) suggestions only.
SECURITY_ADVISORY = {
    "FTP": "Consider disabling anonymous FTP and migrating to SFTP/FTPS.",
    "TELNET": "Telnet transmits data in plaintext - replace with SSH.",
    "SSH": "Ensure key-based auth is enforced and root login is disabled.",
    "HTTP": "Verify TLS is available (HTTPS) and security headers are set.",
    "HTTPS": "Confirm certificate validity and disable outdated TLS versions.",
    "SMB": "Restrict SMB exposure to trusted networks; keep patched.",
    "RDP": "Expose RDP only via VPN; enable Network Level Authentication.",
    "MYSQL": "Ensure database is not exposed publicly; enforce strong auth.",
    "POSTGRESQL": "Ensure database is not exposed publicly; enforce strong auth.",
    "REDIS": "Redis without authentication is high-risk - enable requirepass.",
    "MONGODB": "Ensure authentication is enabled and bind_ip is restricted.",
    "VNC": "VNC without a strong password is high-risk - restrict access.",
    "TELNET-ALT": "Avoid legacy remote-admin protocols where possible.",
    "SNMP": "Use SNMPv3 with authentication instead of default community strings.",
    "ELASTICSEARCH": "Ensure the cluster requires authentication and is firewalled.",
    "DOCKER": "The Docker API should never be exposed without TLS + auth.",
}


def get_service_name(port: int) -> str:
    """
    Resolve a well-known service name for a given port number.
    Falls back to the OS services database, then to 'unknown'.

    Args:
        port: TCP port number.

    Returns:
        Best-effort service name string.
    """
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "unknown"


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """
    Attempt to grab a service banner by connecting and reading the
    first bytes the service sends, optionally sending a minimal probe
    for protocols that expect the client to speak first (e.g., HTTP).

    Args:
        ip: Target IP address.
        port: Target port.
        timeout: Socket timeout in seconds.

    Returns:
        Cleaned banner string, or an empty string if unavailable.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))

            # Some services (HTTP-like) wait for the client to send
            # data first before responding with a banner.
            if port in (80, 8080, 8000, 8888):
                probe = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                sock.sendall(probe.encode(errors="ignore"))
            elif port in (443, 8443):
                # Avoid a raw TLS handshake here to keep this beginner
                # friendly; banner grabbing on TLS ports typically
                # requires an SSL wrapper, so we skip active probing.
                return ""

            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
            # Collapse to a single line for clean table display
            return banner.replace("\r", " ").replace("\n", " ")[:120]
    except Exception:
        return ""


def guess_version_from_banner(banner: str) -> str:
    """
    Extract a lightweight, human-readable "version" hint from a raw
    banner string using simple keyword matching. This is intentionally
    simple and safe - no exploit fingerprinting logic is included.

    Args:
        banner: Raw banner text captured from the service.

    Returns:
        A short version/description string, or 'Unknown'.
    """
    if not banner:
        return "Unknown"

    lowered = banner.lower()
    keywords = [
        "openssh", "apache", "nginx", "microsoft-iis", "postfix",
        "exim", "proftpd", "vsftpd", "pure-ftpd", "mysql", "mariadb",
        "postgresql", "redis", "mongodb", "iis", "lighttpd",
    ]
    for kw in keywords:
        if kw in lowered:
            # Return the original-cased snippet around the keyword
            idx = lowered.find(kw)
            snippet = banner[idx: idx + 40].split()[0:3]
            return " ".join(snippet)

    # Fall back to first few words of the banner
    words = banner.split()
    return " ".join(words[:4]) if words else "Unknown"


def get_security_note(service_name: str) -> str:
    """
    Return a short, defensive hardening reminder for a given service
    name, if one is known. Returns an empty string otherwise.

    Args:
        service_name: Service name (e.g., 'SSH', 'HTTP').

    Returns:
        Advisory string or empty string.
    """
    return SECURITY_ADVISORY.get(service_name.upper(), "")
