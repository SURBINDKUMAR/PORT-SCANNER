# 🛡️ Advanced Port Scanner

A professional-grade, multi-threaded port scanning application with a
dark cybersecurity-themed GUI, built in Python for **ethical hacking
education, security labs, and authorized network assessments.**

> ⚠️ **LEGAL & ETHICAL USE ONLY**
> This tool must only be used against systems you **own** or have
> **explicit written authorization** to test (e.g., a personal lab, a
> CTF range, or a signed penetration-testing engagement). Unauthorized
> scanning of networks or systems may be **illegal** under laws such as
> the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, or
> equivalent legislation in your country. You are solely responsible
> for how you use this software.

---

## ✨ Features

### Scanning Engine
- **TCP Connect Scan** — reliable, works without special privileges
- **SYN Scan** (optional) — via `scapy`, requires root/admin; falls
  back automatically to TCP Connect if unavailable
- Scan **specific ports**, **port ranges** (`1-1024`), **comma lists**
  (`22,80,443`), or the built-in **common ports** list
- **Multi-threaded** (configurable thread pool) for fast scanning
- Configurable **timeout** handling and graceful **Stop Scan** support

### Service & Version Detection
- Well-known service name lookup (SSH, HTTP, HTTPS, SMB, RDP, MySQL...)
- Lightweight **banner grabbing** for open ports
- Simple keyword-based **version hints** parsed from banners
- General, non-exploitative **hardening reminders** per service

### Network Information
- Domain → IP resolution (and reverse lookup)
- Target hostname, resolved IP, and scan timestamps
- Basic **OS fingerprinting heuristic** based on ICMP TTL values

### GUI Dashboard (Tkinter)
- Dark, enterprise-style **cybersecurity theme**
- Target/port/scan-type inputs, thread control
- **Start / Stop** scan buttons
- Live **progress bar** and status line
- Color-coded **results table**:
  - 🟢 Green = OPEN
  - 🔴 Red = CLOSED
  - 🟡 Yellow = FILTERED
- Target information side panel (IP, hostname, OS guess, timing)
- One-click **Export** to CSV, TXT, or PDF

### Reporting
- **CSV** export (spreadsheet-friendly)
- **TXT** export (readable plain-text report)
- **PDF** export (professional report layout, via `reportlab`)
- **Scan history** saved locally (`logs/scan_history.json`)
- Rotating **log files** (`logs/scanner.log`) for auditing/debugging

### Command-Line Mode
Everything in the GUI is also available from the terminal — useful for
scripting, automation, or headless/lab environments.

---

## 🗂️ Project Structure

```
Advanced-Port-Scanner/
│
├── main.py                     # Entry point (GUI by default, --cli for terminal mode)
├── scanner/
│   ├── __init__.py
│   ├── port_scanner.py         # Core scanning engine (TCP Connect + optional SYN)
│   ├── service_detection.py    # Service name lookup, banner grabbing, version hints
│   ├── network_info.py         # DNS resolution, target info, TTL-based OS guess
│   ├── report_generator.py     # CSV / TXT / PDF report export
│   ├── history.py              # JSON scan history persistence
│   └── logger_setup.py         # Centralized logging configuration
│
├── gui/
│   ├── __init__.py
│   └── dashboard.py             # Tkinter dark-themed dashboard
│
├── reports/                     # Exported CSV/TXT/PDF reports land here
├── logs/                        # scanner.log + scan_history.json
│
├── requirements.txt
├── README.md
└── LICENSE
```

---

## 📦 Requirements

- **Python 3.9+**
- Tkinter (bundled with most Python installers; on Debian/Ubuntu:
  `sudo apt install python3-tk`)
- Optional Python packages (see `requirements.txt`):
  - `scapy` — enables SYN scanning (requires root/admin at runtime)
  - `reportlab` — enables PDF report export

---

## ⚙️ Installation

```bash
# 1. Clone or download this project
cd Advanced-Port-Scanner

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

The tool works even if `scapy` or `reportlab` are not installed — it
simply disables SYN scanning and/or PDF export and tells you how to
enable them.

---

## 🚀 Usage

### GUI Mode (default)

```bash
python main.py
```

1. Enter a **target** (IP address or domain you are authorized to test).
2. Enter **ports** — `common`, `80`, `1-1024`, or `22,80,443`.
3. Choose **TCP Connect** or **SYN (Stealth)** (SYN needs root/admin).
4. Click **▶ START SCAN**. Results stream in live, color-coded.
5. Click **■ STOP SCAN** any time to cancel gracefully.
6. Use **Export CSV / TXT / PDF Report** to save your findings.

### CLI Mode

```bash
# Quick scan of common ports
python main.py --cli --target scanme.nmap.org --ports common

# Scan a full range with more threads
python main.py --cli --target 192.168.1.10 --ports 1-1024 --threads 200

# SYN scan (requires sudo/admin + scapy installed)
sudo python main.py --cli --target 192.168.1.10 --ports 22,80,443 --type syn

# Export results directly
python main.py --cli --target 192.168.1.10 --ports common --export csv,txt,pdf
```

Run `python main.py --cli --help` for the full list of CLI options.

---

## 🖼️ Screenshots / Mockup Description

*(Actual screenshots depend on your OS's Tkinter theme rendering —
below is a description of the intended look for reference.)*

- **Header bar**: Black background, neon-green shield icon and title
  "ADVANCED PORT SCANNER", with a yellow "Authorized Testing Only"
  sub-label.
- **Input panel**: Graphite (`#161b22`) card containing the target
  field, port field, scan-type dropdown, thread spinner, and large
  green "▶ START SCAN" / red "■ STOP SCAN" buttons.
- **Left sidebar**: "TARGET INFORMATION" panel showing resolved IP,
  hostname, OS guess, and scan timing in a monospace terminal-style
  text box.
- **Main table**: "SCAN RESULTS" grid with columns `PORT | STATE |
  SERVICE | VERSION | BANNER`, rows colored green/red/yellow by state.
- **Footer**: A green progress bar, live status text (e.g. "Scanning...
  42/100 ports checked"), and export buttons on the right.

---

## 🧠 How It Works (Beginner-Friendly Overview)

1. **Resolve** the target hostname/IP (`scanner/network_info.py`).
2. **Parse** the requested ports into a list of integers
   (`parse_port_input` in `scanner/port_scanner.py`).
3. **Scan** each port concurrently using a `ThreadPoolExecutor`:
   - *TCP Connect*: attempts a real `connect()` — if it succeeds, the
     port is OPEN.
   - *SYN*: sends a raw SYN packet with `scapy` and inspects the
     response flags (SYN-ACK = open, RST = closed) without completing
     the handshake — hence "stealth"/"half-open".
4. For OPEN ports, **grab a banner** and guess the **service/version**
   (`scanner/service_detection.py`).
5. Results are streamed back to the GUI/CLI in real time via a
   progress callback.
6. Once finished, results can be **exported** and are automatically
   appended to the local **scan history**.

---

## 🔒 Security & Responsible Use

- No exploit code, attack payloads, or vulnerability weaponization is
  included anywhere in this project.
- "Security notes" shown for open services are **generic, defensive
  hardening reminders** only (e.g., "disable anonymous FTP") — not
  attack guidance.
- SYN scanning is implemented using the same technique found in
  well-known, widely taught tools (e.g., Nmap) and requires elevated
  privileges by design — it is not a covert or illegal capability.
- Always obtain **written authorization** before scanning any system
  you do not personally own.

---

## 🛠️ Future Improvements

- IPv6 scanning support
- UDP port scanning
- Nmap-style OS fingerprinting (TCP/IP stack analysis, not just TTL)
- Scan result diffing between two historical scans
- Scheduled/recurring scans with email/webhook alerts
- Plugin system for custom service probes
- Dark/light theme toggle and high-DPI scaling
- Packaged binaries (PyInstaller) for Windows/macOS/Linux

---

## 📄 License

Released under the MIT License — see [LICENSE](LICENSE) for details,
including the additional ethical-use notice.
