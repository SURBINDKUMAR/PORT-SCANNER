"""
report_generator.py
---------------------
Generates exportable scan reports in CSV, TXT, and PDF formats.

PDF generation uses ReportLab if available. If ReportLab is not
installed, PDF export is skipped gracefully with a clear message,
so the rest of the application keeps working.
"""

import csv
import os
from datetime import datetime

from scanner.port_scanner import ScanSummary

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


def _default_filename(target: str, ext: str) -> str:
    safe_target = target.replace(".", "_").replace(":", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"scan_{safe_target}_{stamp}.{ext}"


def export_csv(summary: ScanSummary, output_dir: str, filename: str = None) -> str:
    """
    Export scan results to a CSV file.

    Returns:
        Full path to the created file.
    """
    filename = filename or _default_filename(summary.target, "csv")
    path = os.path.join(output_dir, filename)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", summary.target])
        writer.writerow(["Scan Type", summary.scan_type])
        writer.writerow(["Start Time", summary.start_time])
        writer.writerow(["End Time", summary.end_time])
        writer.writerow(["Duration (s)", summary.duration_seconds])
        writer.writerow([])
        writer.writerow(["PORT", "STATE", "SERVICE", "VERSION", "BANNER", "NOTE"])
        for r in summary.all_results:
            writer.writerow([r.port, r.state, r.service, r.version, r.banner, r.security_note])

    return path


def export_txt(summary: ScanSummary, output_dir: str, filename: str = None) -> str:
    """
    Export scan results to a plain-text report.

    Returns:
        Full path to the created file.
    """
    filename = filename or _default_filename(summary.target, "txt")
    path = os.path.join(output_dir, filename)

    lines = []
    lines.append("=" * 60)
    lines.append("ADVANCED PORT SCANNER - SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"Target:        {summary.target}")
    lines.append(f"Scan Type:     {summary.scan_type}")
    lines.append(f"Start Time:    {summary.start_time}")
    lines.append(f"End Time:      {summary.end_time}")
    lines.append(f"Duration:      {summary.duration_seconds}s")
    lines.append(f"Ports Scanned: {summary.total_ports_scanned}")
    lines.append(f"Open Ports:    {len(summary.open_ports)}")
    lines.append(f"Closed Ports:  {summary.closed_count}")
    lines.append(f"Filtered:      {summary.filtered_count}")
    lines.append("-" * 60)
    lines.append(f"{'PORT':<8}{'STATE':<12}{'SERVICE':<16}{'VERSION':<20}")
    lines.append("-" * 60)
    for r in summary.all_results:
        lines.append(f"{r.port:<8}{r.state:<12}{r.service:<16}{r.version:<20}")

    if any(r.security_note for r in summary.open_ports):
        lines.append("-" * 60)
        lines.append("SECURITY NOTES (general hardening reminders):")
        for r in summary.open_ports:
            if r.security_note:
                lines.append(f"  [{r.port}/{r.service}] {r.security_note}")

    lines.append("=" * 60)
    lines.append("Disclaimer: For authorized security testing and")
    lines.append("educational use only.")
    lines.append("=" * 60)

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return path


def export_pdf(summary: ScanSummary, output_dir: str, filename: str = None) -> str:
    """
    Export a professional-looking PDF security report.

    Raises:
        RuntimeError: If ReportLab is not installed.

    Returns:
        Full path to the created PDF file.
    """
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError(
            "PDF export requires the 'reportlab' package. "
            "Install it with: pip install reportlab"
        )

    filename = filename or _default_filename(summary.target, "pdf")
    path = os.path.join(output_dir, filename)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleDark", parent=styles["Title"], textColor=colors.HexColor("#00ff9c")
    )
    normal = styles["Normal"]

    doc = SimpleDocTemplate(path, pagesize=A4, title="Port Scan Report")
    elements = []

    elements.append(Paragraph("Advanced Port Scanner - Security Report", title_style))
    elements.append(Spacer(1, 8))

    meta_data = [
        ["Target", summary.target],
        ["Scan Type", summary.scan_type],
        ["Start Time", summary.start_time],
        ["End Time", summary.end_time],
        ["Duration (s)", str(summary.duration_seconds)],
        ["Ports Scanned", str(summary.total_ports_scanned)],
        ["Open", str(len(summary.open_ports))],
        ["Closed", str(summary.closed_count)],
        ["Filtered", str(summary.filtered_count)],
    ]
    meta_table = Table(meta_data, colWidths=[120, 300])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1c1c1c")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 16))

    elements.append(Paragraph("Port Scan Results", styles["Heading2"]))
    table_data = [["Port", "State", "Service", "Version"]]
    for r in summary.all_results:
        table_data.append([str(r.port), r.state, r.service, r.version])

    results_table = Table(table_data, colWidths=[60, 80, 120, 160], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0a0a0a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#00ff9c")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]
    for row_idx, r in enumerate(summary.all_results, start=1):
        if r.state == "OPEN":
            style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), colors.green))
        elif r.state == "CLOSED":
            style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), colors.red))
        elif r.state == "FILTERED":
            style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), colors.orange))

    results_table.setStyle(TableStyle(style_cmds))
    elements.append(results_table)
    elements.append(Spacer(1, 16))

    notes = [r for r in summary.open_ports if r.security_note]
    if notes:
        elements.append(Paragraph("General Hardening Reminders", styles["Heading2"]))
        for r in notes:
            elements.append(Paragraph(f"<b>{r.port}/{r.service}</b>: {r.security_note}", normal))
        elements.append(Spacer(1, 12))

    elements.append(Paragraph(
        "<i>Disclaimer: This report was generated for authorized security "
        "testing and educational purposes only.</i>", normal
    ))

    doc.build(elements)
    return path
