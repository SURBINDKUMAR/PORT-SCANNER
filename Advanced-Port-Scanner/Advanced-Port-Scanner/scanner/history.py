"""
history.py
-----------
Simple JSON-based scan history persistence, so users can review
past scans (target, time, open port count) between sessions.
"""

import json
import os
from typing import List, Dict

from scanner.port_scanner import ScanSummary


def _history_path(history_dir: str = "logs") -> str:
    os.makedirs(history_dir, exist_ok=True)
    return os.path.join(history_dir, "scan_history.json")


def save_scan_to_history(summary: ScanSummary, history_dir: str = "logs") -> None:
    """
    Append a completed scan's summary metadata to the history file.

    Args:
        summary: The ScanSummary to record.
        history_dir: Directory containing the history JSON file.
    """
    path = _history_path(history_dir)
    history = load_history(history_dir)

    history.append({
        "target": summary.target,
        "resolved_ip": summary.resolved_ip,
        "scan_type": summary.scan_type,
        "start_time": summary.start_time,
        "end_time": summary.end_time,
        "duration_seconds": summary.duration_seconds,
        "ports_scanned": summary.total_ports_scanned,
        "open_ports": [r.port for r in summary.open_ports],
    })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


def load_history(history_dir: str = "logs") -> List[Dict]:
    """
    Load previously saved scan history.

    Returns:
        List of scan history records (may be empty).
    """
    path = _history_path(history_dir)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
