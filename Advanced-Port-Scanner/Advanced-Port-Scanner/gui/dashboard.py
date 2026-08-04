"""
dashboard.py
-------------
Tkinter-based GUI dashboard for the Advanced Port Scanner, styled with
a dark "cybersecurity" theme (black/graphite background, neon-green
accents). Runs scans on a background thread so the UI never freezes,
and streams results into the table in real time.
"""

import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from scanner.port_scanner import PortScanner, parse_port_input, COMMON_PORTS
from scanner.network_info import get_target_info, ping_ttl, guess_os_from_ttl
from scanner.report_generator import export_csv, export_txt, export_pdf, REPORTLAB_AVAILABLE
from scanner.history import save_scan_to_history
from scanner.logger_setup import setup_logging

logger = setup_logging()

# ---------------------------------------------------------------------
# Color palette - dark cybersecurity theme
# ---------------------------------------------------------------------
BG_MAIN = "#0d1117"
BG_PANEL = "#161b22"
BG_INPUT = "#010409"
FG_TEXT = "#c9d1d9"
ACCENT_GREEN = "#00ff9c"
ACCENT_RED = "#ff4d4d"
ACCENT_YELLOW = "#ffd60a"
ACCENT_BLUE = "#58a6ff"
BORDER_COLOR = "#30363d"

FONT_HEADER = ("Consolas", 18, "bold")
FONT_LABEL = ("Consolas", 10)
FONT_MONO = ("Consolas", 10)


class PortScannerDashboard(tk.Tk):
    """Main application window for the Advanced Port Scanner GUI."""

    def __init__(self):
        super().__init__()
        self.title("Advanced Port Scanner  |  Ethical Hacking Toolkit")
        self.geometry("1150x720")
        self.configure(bg=BG_MAIN)
        self.minsize(950, 620)

        self.scanner = PortScanner()
        self.scan_thread = None
        self.current_summary = None
        self.is_scanning = False

        self._build_style()
        self._build_layout()

    # ------------------------------------------------------------------
    # Styling
    # ------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TFrame", background=BG_MAIN)
        style.configure("Panel.TFrame", background=BG_PANEL)

        style.configure(
            "TLabel", background=BG_MAIN, foreground=FG_TEXT, font=FONT_LABEL
        )
        style.configure(
            "Panel.TLabel", background=BG_PANEL, foreground=FG_TEXT, font=FONT_LABEL
        )
        style.configure(
            "Header.TLabel", background=BG_MAIN, foreground=ACCENT_GREEN,
            font=FONT_HEADER
        )

        style.configure(
            "Accent.TButton", background=ACCENT_GREEN, foreground="#000000",
            font=("Consolas", 10, "bold"), padding=6, borderwidth=0
        )
        style.map("Accent.TButton", background=[("active", "#00cc7d")])

        style.configure(
            "Danger.TButton", background=ACCENT_RED, foreground="#000000",
            font=("Consolas", 10, "bold"), padding=6, borderwidth=0
        )
        style.map("Danger.TButton", background=[("active", "#cc3d3d")])

        style.configure(
            "Secondary.TButton", background=BG_PANEL, foreground=ACCENT_BLUE,
            font=("Consolas", 9, "bold"), padding=5, borderwidth=1
        )

        style.configure(
            "TEntry", fieldbackground=BG_INPUT, foreground=FG_TEXT,
            insertcolor=FG_TEXT, borderwidth=1
        )
        style.configure(
            "TCombobox", fieldbackground=BG_INPUT, foreground=FG_TEXT
        )

        style.configure(
            "Horizontal.TProgressbar", background=ACCENT_GREEN,
            troughcolor=BG_INPUT, borderwidth=0
        )

        style.configure(
            "Treeview", background=BG_INPUT, foreground=FG_TEXT,
            fieldbackground=BG_INPUT, rowheight=24, font=FONT_MONO,
            borderwidth=0
        )
        style.configure(
            "Treeview.Heading", background=BG_PANEL, foreground=ACCENT_GREEN,
            font=("Consolas", 10, "bold")
        )
        style.map("Treeview", background=[("selected", "#1f6feb")])

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build_layout(self):
        # Header
        header = ttk.Frame(self, style="TFrame")
        header.pack(fill="x", padx=20, pady=(15, 5))
        ttk.Label(header, text="⛨ ADVANCED PORT SCANNER", style="Header.TLabel").pack(side="left")
        ttk.Label(
            header, text="  Authorized Security Testing & Education Only",
            style="TLabel", foreground=ACCENT_YELLOW
        ).pack(side="left", padx=10)

        # Input Panel
        input_panel = ttk.Frame(self, style="Panel.TFrame")
        input_panel.pack(fill="x", padx=20, pady=8)
        self._build_input_panel(input_panel)

        # Middle split: target info (left) + results table (right)
        middle = ttk.Frame(self, style="TFrame")
        middle.pack(fill="both", expand=True, padx=20, pady=8)

        info_panel = ttk.Frame(middle, style="Panel.TFrame", width=260)
        info_panel.pack(side="left", fill="y", padx=(0, 10))
        self._build_info_panel(info_panel)

        results_panel = ttk.Frame(middle, style="Panel.TFrame")
        results_panel.pack(side="left", fill="both", expand=True)
        self._build_results_panel(results_panel)

        # Footer: progress + export
        footer = ttk.Frame(self, style="TFrame")
        footer.pack(fill="x", padx=20, pady=(5, 15))
        self._build_footer(footer)

    def _build_input_panel(self, parent):
        pad = {"padx": 8, "pady": 8}

        ttk.Label(parent, text="Target (IP / Domain):", style="Panel.TLabel").grid(
            row=0, column=0, sticky="w", **pad
        )
        self.target_entry = ttk.Entry(parent, width=24, style="TEntry")
        self.target_entry.insert(0, "scanme.nmap.org")
        self.target_entry.grid(row=0, column=1, **pad)

        ttk.Label(parent, text="Ports:", style="Panel.TLabel").grid(
            row=0, column=2, sticky="w", **pad
        )
        self.port_entry = ttk.Entry(parent, width=20, style="TEntry")
        self.port_entry.insert(0, "common")
        self.port_entry.grid(row=0, column=3, **pad)
        ttk.Label(
            parent, text="(e.g. 80  |  1-1024  |  22,80,443  |  common)",
            style="Panel.TLabel", foreground="#8b949e", font=("Consolas", 8)
        ).grid(row=0, column=4, sticky="w", **pad)

        ttk.Label(parent, text="Scan Type:", style="Panel.TLabel").grid(
            row=1, column=0, sticky="w", **pad
        )
        self.scan_type_var = tk.StringVar(value="TCP Connect")
        scan_type_box = ttk.Combobox(
            parent, textvariable=self.scan_type_var, width=15, state="readonly",
            values=["TCP Connect", "SYN (Stealth)"]
        )
        scan_type_box.grid(row=1, column=1, **pad)

        ttk.Label(parent, text="Threads:", style="Panel.TLabel").grid(
            row=1, column=2, sticky="w", **pad
        )
        self.thread_var = tk.IntVar(value=100)
        thread_spin = tk.Spinbox(
            parent, from_=10, to=500, increment=10, textvariable=self.thread_var,
            width=6, bg=BG_INPUT, fg=FG_TEXT, insertbackground=FG_TEXT,
            relief="flat"
        )
        thread_spin.grid(row=1, column=3, sticky="w", **pad)

        self.start_btn = ttk.Button(
            parent, text="▶  START SCAN", style="Accent.TButton", command=self.start_scan
        )
        self.start_btn.grid(row=0, column=5, rowspan=1, padx=10, pady=8)

        self.stop_btn = ttk.Button(
            parent, text="■  STOP SCAN", style="Danger.TButton",
            command=self.stop_scan, state="disabled"
        )
        self.stop_btn.grid(row=1, column=5, rowspan=1, padx=10, pady=8)

    def _build_info_panel(self, parent):
        ttk.Label(parent, text="TARGET INFORMATION", style="Panel.TLabel",
                  font=("Consolas", 11, "bold"), foreground=ACCENT_GREEN
                  ).pack(anchor="w", padx=10, pady=(10, 5))

        self.info_text = tk.Text(
            parent, width=32, height=16, bg=BG_INPUT, fg=FG_TEXT,
            font=FONT_MONO, relief="flat", wrap="word"
        )
        self.info_text.pack(fill="both", expand=True, padx=10, pady=5)
        self.info_text.insert("end", "No scan run yet.\n")
        self.info_text.config(state="disabled")

    def _build_results_panel(self, parent):
        ttk.Label(parent, text="SCAN RESULTS", style="Panel.TLabel",
                  font=("Consolas", 11, "bold"), foreground=ACCENT_GREEN
                  ).pack(anchor="w", padx=10, pady=(10, 5))

        columns = ("port", "state", "service", "version", "banner")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", height=18)
        headings = {
            "port": ("PORT", 60), "state": ("STATE", 90),
            "service": ("SERVICE", 110), "version": ("VERSION", 220),
            "banner": ("BANNER", 260),
        }
        for col, (text, width) in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="w")

        self.tree.tag_configure("open", foreground=ACCENT_GREEN)
        self.tree.tag_configure("closed", foreground=ACCENT_RED)
        self.tree.tag_configure("filtered", foreground=ACCENT_YELLOW)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=5)
        vsb.pack(side="left", fill="y", pady=5)

    def _build_footer(self, parent):
        self.progress = ttk.Progressbar(
            parent, orient="horizontal", mode="determinate",
            style="Horizontal.TProgressbar"
        )
        self.progress.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(parent, textvariable=self.status_var, style="TLabel").pack(
            side="left", padx=10
        )

        ttk.Button(
            parent, text="Export CSV", style="Secondary.TButton",
            command=lambda: self.export_report("csv")
        ).pack(side="right", padx=4)
        ttk.Button(
            parent, text="Export TXT", style="Secondary.TButton",
            command=lambda: self.export_report("txt")
        ).pack(side="right", padx=4)
        ttk.Button(
            parent, text="Export PDF Report", style="Secondary.TButton",
            command=lambda: self.export_report("pdf")
        ).pack(side="right", padx=4)

    # ------------------------------------------------------------------
    # Scan control
    # ------------------------------------------------------------------
    def start_scan(self):
        if self.is_scanning:
            return

        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target IP or domain.")
            return

        try:
            ports = parse_port_input(self.port_entry.get())
        except ValueError as exc:
            messagebox.showerror("Invalid Port Input", str(exc))
            return

        self.tree.delete(*self.tree.get_children())
        self._set_info_text("Resolving target...\n")
        self.status_var.set("Resolving target...")
        self.progress["value"] = 0
        self.progress["maximum"] = len(ports)

        self.scanner.max_threads = self.thread_var.get()

        self.is_scanning = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

        self.scan_thread = threading.Thread(
            target=self._run_scan_worker, args=(target, ports), daemon=True
        )
        self.scan_thread.start()

    def stop_scan(self):
        if self.is_scanning:
            self.scanner.stop()
            self.status_var.set("Stopping scan...")
            logger.info("User requested scan stop.")

    def _run_scan_worker(self, target: str, ports: list):
        """Runs in a background thread - must not touch widgets directly
        except via self.after(...) to stay thread-safe."""
        try:
            info = get_target_info(target)
            if info["resolved_ip"] == "Unresolved":
                self.after(0, self._on_resolve_failed, target)
                return

            ip = info["resolved_ip"]
            self.after(0, self._update_info_panel_initial, info)

            scan_type = self.scan_type_var.get()

            def progress_cb(result, completed, total):
                self.after(0, self._on_port_result, result, completed, total)

            summary = self.scanner.scan(
                ip=ip, ports=ports, scan_type=scan_type, progress_callback=progress_cb
            )
            self.current_summary = summary
            summary.target = target  # preserve user-entered value for reports

            # Basic OS fingerprint (best effort, non-intrusive ping)
            ttl = ping_ttl(ip)
            os_guess = guess_os_from_ttl(ttl)

            save_scan_to_history(summary)
            self.after(0, self._on_scan_complete, summary, os_guess)

        except Exception as exc:
            logger.exception("Unexpected error during scan.")
            self.after(0, self._on_scan_error, str(exc))

    # ------------------------------------------------------------------
    # UI callbacks (always run on main thread via self.after)
    # ------------------------------------------------------------------
    def _on_resolve_failed(self, target):
        self.is_scanning = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Error: could not resolve target.")
        messagebox.showerror("Resolution Failed", f"Could not resolve target: {target}")

    def _update_info_panel_initial(self, info):
        text = (
            f"Input Target : {info['input_target']}\n"
            f"Resolved IP  : {info['resolved_ip']}\n"
            f"Hostname     : {info['hostname']}\n"
            f"Scan Started : {info['scan_start_time']}\n"
            f"OS Guess     : Pending...\n"
        )
        self._set_info_text(text)
        self.status_var.set("Scanning in progress...")

    def _on_port_result(self, result, completed, total):
        tag = result.state.lower()
        self.tree.insert(
            "", "end",
            values=(result.port, result.state, result.service, result.version, result.banner),
            tags=(tag,)
        )
        self.progress["value"] = completed
        self.status_var.set(f"Scanning... {completed}/{total} ports checked")

    def _on_scan_complete(self, summary, os_guess):
        self.is_scanning = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

        text = (
            f"Input Target : {summary.target}\n"
            f"Resolved IP  : {summary.resolved_ip}\n"
            f"Scan Type    : {summary.scan_type}\n"
            f"Start Time   : {summary.start_time}\n"
            f"End Time     : {summary.end_time}\n"
            f"Duration     : {summary.duration_seconds}s\n"
            f"OS Guess     : {os_guess}\n"
            f"\n"
            f"Ports Scanned: {summary.total_ports_scanned}\n"
            f"Open         : {len(summary.open_ports)}\n"
            f"Closed       : {summary.closed_count}\n"
            f"Filtered     : {summary.filtered_count}\n"
        )
        self._set_info_text(text)
        self.status_var.set(
            f"Scan complete. {len(summary.open_ports)} open port(s) found."
        )
        logger.info(
            f"Scan complete for {summary.target}: "
            f"{len(summary.open_ports)} open ports found."
        )

    def _on_scan_error(self, error_message):
        self.is_scanning = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_var.set("Scan failed - see logs.")
        messagebox.showerror("Scan Error", error_message)

    def _set_info_text(self, text: str):
        self.info_text.config(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("end", text)
        self.info_text.config(state="disabled")

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export_report(self, fmt: str):
        if not self.current_summary:
            messagebox.showinfo("No Data", "Run a scan before exporting a report.")
            return

        if fmt == "pdf" and not REPORTLAB_AVAILABLE:
            messagebox.showwarning(
                "ReportLab Not Installed",
                "PDF export requires the 'reportlab' package.\n"
                "Install it with: pip install reportlab"
            )
            return

        output_dir = filedialog.askdirectory(title="Select export folder")
        if not output_dir:
            return

        try:
            if fmt == "csv":
                path = export_csv(self.current_summary, output_dir)
            elif fmt == "txt":
                path = export_txt(self.current_summary, output_dir)
            elif fmt == "pdf":
                path = export_pdf(self.current_summary, output_dir)
            else:
                return

            messagebox.showinfo("Export Successful", f"Report saved to:\n{path}")
            logger.info(f"Report exported: {path}")
        except Exception as exc:
            logger.exception("Report export failed.")
            messagebox.showerror("Export Failed", str(exc))


def run_dashboard():
    """Entry point used by main.py to launch the GUI."""
    app = PortScannerDashboard()
    app.mainloop()
