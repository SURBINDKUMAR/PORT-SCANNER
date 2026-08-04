#!/usr/bin/env python3
"""
main.py
--------
Entry point for the Advanced Port Scanner.

Usage:
    GUI mode (default):
        python main.py

    CLI mode:
        python main.py --cli --target scanme.nmap.org --ports common
        python main.py --cli --target 192.168.1.10 --ports 1-1024 --type syn
        python main.py --cli --target 10.0.0.5 --ports 22,80,443 --export csv,pdf

LEGAL / ETHICAL NOTICE
-----------------------
This tool is intended ONLY for authorized security testing, lab
environments, and educational use. Scanning systems without explicit
permission may be illegal. You are solely responsible for how you
use this software.
"""

import sys
import argparse

from scanner.port_scanner import PortScanner, parse_port_input
from scanner.network_info import get_target_info, ping_ttl, guess_os_from_ttl
from scanner.report_generator import export_csv, export_txt, export_pdf, REPORTLAB_AVAILABLE
from scanner.history import save_scan_to_history
from scanner.logger_setup import setup_logging

DISCLAIMER = (
    "=" * 70 + "\n"
    "ADVANCED PORT SCANNER - For authorized security testing & education ONLY\n"
    "Do not scan systems you do not own or lack explicit permission to test.\n"
    + "=" * 70
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner - GUI and CLI ethical hacking tool."
    )
    parser.add_argument("--cli", action="store_true", help="Run in command-line mode instead of GUI.")
    parser.add_argument("--target", type=str, help="Target IP address or domain name.")
    parser.add_argument(
        "--ports", type=str, default="common",
        help="Ports to scan: 'common', a single port, a range (1-1024), "
             "or a comma list (22,80,443). Default: common"
    )
    parser.add_argument(
        "--type", type=str, choices=["tcp", "syn"], default="tcp",
        help="Scan type: 'tcp' (TCP Connect) or 'syn' (requires root/admin + scapy)."
    )
    parser.add_argument("--threads", type=int, default=100, help="Max concurrent threads (default: 100).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port timeout in seconds (default: 1.0).")
    parser.add_argument(
        "--no-service-detect", action="store_true",
        help="Disable banner grabbing / version detection (faster scan)."
    )
    parser.add_argument(
        "--export", type=str, default="",
        help="Comma-separated export formats: csv,txt,pdf. Saved to ./reports/"
    )
    return parser


def run_cli(args):
    print(DISCLAIMER)

    if not args.target:
        print("Error: --target is required in CLI mode.")
        sys.exit(1)

    try:
        ports = parse_port_input(args.ports)
    except ValueError as exc:
        print(f"Error: {exc}")
        sys.exit(1)

    print(f"\n[*] Resolving target: {args.target} ...")
    info = get_target_info(args.target)
    if info["resolved_ip"] == "Unresolved":
        print(f"[!] Could not resolve target '{args.target}'. Exiting.")
        sys.exit(1)

    ip = info["resolved_ip"]
    print(f"[*] Resolved IP   : {ip}")
    print(f"[*] Hostname      : {info['hostname']}")
    print(f"[*] Ports to scan : {len(ports)}")
    print(f"[*] Scan type     : {'SYN' if args.type == 'syn' else 'TCP Connect'}")
    print("[*] Starting scan...\n")

    scanner = PortScanner(
        max_threads=args.threads,
        timeout=args.timeout,
        detect_services=not args.no_service_detect,
    )

    def progress_cb(result, completed, total):
        if result.state == "OPEN":
            print(f"  [{completed}/{total}] Port {result.port:<6} OPEN    "
                  f"{result.service:<12} {result.version}")

    scan_type_label = "SYN (Stealth)" if args.type == "syn" else "TCP Connect"
    summary = scanner.scan(ip=ip, ports=ports, scan_type=scan_type_label, progress_callback=progress_cb)
    summary.target = args.target

    ttl = ping_ttl(ip)
    os_guess = guess_os_from_ttl(ttl)

    print("\n" + "-" * 60)
    print(f"{'PORT':<8}{'STATE':<12}{'SERVICE':<16}{'VERSION':<20}")
    print("-" * 60)
    for r in summary.all_results:
        print(f"{r.port:<8}{r.state:<12}{r.service:<16}{r.version:<20}")
    print("-" * 60)
    print(f"Scanned {summary.total_ports_scanned} ports in {summary.duration_seconds}s")
    print(f"Open: {len(summary.open_ports)}  Closed: {summary.closed_count}  "
          f"Filtered: {summary.filtered_count}")
    print(f"OS Guess (heuristic): {os_guess}")

    save_scan_to_history(summary)

    if args.export:
        formats = [f.strip().lower() for f in args.export.split(",") if f.strip()]
        for fmt in formats:
            try:
                if fmt == "csv":
                    path = export_csv(summary, "reports")
                elif fmt == "txt":
                    path = export_txt(summary, "reports")
                elif fmt == "pdf":
                    if not REPORTLAB_AVAILABLE:
                        print("[!] Skipping PDF export - install 'reportlab' first.")
                        continue
                    path = export_pdf(summary, "reports")
                else:
                    print(f"[!] Unknown export format: {fmt}")
                    continue
                print(f"[+] Report saved: {path}")
            except Exception as exc:
                print(f"[!] Failed to export {fmt}: {exc}")


def main():
    setup_logging()
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.cli:
        run_cli(args)
    else:
        # Import here so CLI-only environments don't require a display server.
        from gui.dashboard import run_dashboard
        run_dashboard()


if __name__ == "__main__":
    main()
