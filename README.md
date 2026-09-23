# Mini Port Scanner

A lightweight, defensive TCP port scanner for the Linux desktop, built with **Python 3.10+** and **PySide6 (Qt 6)**.
Enter a host, pick a port range, and see which TCP ports are open — without freezing the UI, without a database, and without any external service.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![PySide6](https://img.shields.io/badge/GUI-PySide6%20(Qt%206)-41CD52?logo=qt&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-blue)

---

## Overview

Mini Port Scanner is a small learning / lab utility for **authorized** security testing.
It performs a plain TCP connect scan (`socket.connect`) against a single host and reports open ports with a best-effort service name.
The scanning logic (`scanner.py`) is pure standard library and completely separate from the GUI (`main.py`).

It deliberately does **not** do banner grabbing, version detection, stealth techniques or anything offensive.

## Features

- **Target input** — IPv4 / IPv6 address or hostname, validated before the scan starts.
- **Port range** — start / end port (default `1–1000`), limited to `1–65535`, invalid ranges rejected.
- **Non-blocking scanning** — the scan runs in a `QThread` worker with a small thread pool; the GUI never freezes.
- **Start / Stop** — stop a running scan at any time.
- **Real-time progress** — progress bar, scanned-port counter and open-port counter update live.
- **Results table** — open ports only, showing `Port`, `State`, `Service`.
- **Service detection** — `socket.getservbyport()` first, then a built-in fallback table (SSH, FTP, SMTP, DNS, HTTP, POP3, IMAP, HTTPS, MySQL, PostgreSQL, HTTP-Proxy, …).
- **Scan summary** — target, port range, total ports scanned, open ports, scan status.
- **Export** — save results as CSV or TXT.
- **Clear** — reset results, progress, counters, status and inputs.
- **Keyboard shortcuts** — `Ctrl+Enter` start, `Esc` stop, `Ctrl+L` clear.
- **Robust error handling** — invalid input, DNS failures, timeouts, refused connections, permission errors and unreachable hosts are all handled without crashing; a single failed port never aborts the scan.

## Screenshots



| Idle | Scan in progress |
| --- | --- |
|<img width="1366" height="768" alt="Screenshot (540)" src="https://github.com/user-attachments/assets/07c05688-cdc3-4da4-82d0-0bcf677273d2" />
 | <img width="1600" height="900" alt="WhatsApp Image 2026-09-23 at 1 11 22 PM" src="https://github.com/user-attachments/assets/0b6037f0-dc96-4ee0-bc47-b89261acde73" />
 |

## Tech Stack

| Component | Choice |
| --- | --- |
| Language | Python 3.10+ |
| GUI | PySide6 (Qt 6, Fusion style with a dark stylesheet) |
| Networking | `socket`, `ipaddress`, `concurrent.futures`, `threading` (standard library) |
| Export | `csv` and plain text (standard library) |
| Storage | None — no database, no config files |

## Installation

```bash
git clone https://github.com/mukeshsingh82/Port-Scanner.git
cd Port-Scanner

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On very minimal Linux installs Qt may need a few system libraries, e.g. on Debian/Ubuntu:

```bash
sudo apt install libxcb-cursor0 libxkbcommon-x11-0 libgl1
```

No root privileges are required to run the scanner — TCP connect scans use ordinary sockets.

## Usage

```bash
python3 main.py
```

1. Enter a **target** (`127.0.0.1`, `localhost`, `192.168.1.10`, `lab-server`, …).
2. Set the **start** and **end** port (defaults `1` and `1000`).
3. Press **Start Scan** (or `Ctrl+Enter`).
4. Watch the progress bar and counters; open ports appear in the table as they are found.
5. Press **Stop Scan** (or `Esc`) to abort early.
6. Use **Export CSV** / **Export TXT** to save the results, or **Clear** (`Ctrl+L`) to reset everything.

| Shortcut | Action |
| --- | --- |
| `Ctrl+Enter` | Start scan |
| `Esc` | Stop scan |
| `Ctrl+L` | Clear |

Only **open** ports are listed. Closed ports (connection refused) and filtered ports (timeout) are counted in the progress but not shown.

## Example Scan

Scanning `localhost`, ports `1–1000`, on a typical developer machine:

```
Target:              localhost (127.0.0.1)
Port range:          1 - 1000
Total ports scanned: 1000
Open ports:          3
Scan status:         Completed

PORT    STATE     SERVICE
22      OPEN      SSH
80      OPEN      HTTP
631     OPEN      IPP
```

The same data exported as CSV:

```csv
Port,State,Service
22,OPEN,SSH
80,OPEN,HTTP
631,OPEN,IPP
```

## Project Structure

```
Mini-Port-Scanner/
├── main.py            # PySide6 GUI, background worker thread, export
├── scanner.py         # Validation, resolution, TCP connect scanning (stdlib only)
├── requirements.txt   # PySide6
├── README.md
└── .gitignore
```

- `scanner.py` exposes `validate_target()`, `validate_port_range()`, `resolve_target()`, `scan_port()`, `scan_ports()` and `get_service_name()`. It has no Qt dependency.
- `main.py` wraps `scan_ports()` in a `QThread` (`ScanWorker`) and communicates with the window purely through Qt signals.

## Security & Authorized Use

**For authorized security testing and defensive use only.**

Port scanning systems you do not own or have explicit written permission to test may be illegal in your jurisdiction and against your provider's terms of service.
This tool is intended for `localhost`, lab machines and networks where you are authorized to perform testing.

By design the application does **not** implement exploitation, credential attacks, brute forcing, banner grabbing, stealth/evasion techniques or internet-wide scanning.

## Limitations

- TCP connect scans only — no SYN/stealth scans, no UDP.
- No banner grabbing or version detection; service names are a best-effort lookup by port number.
- Results depend on firewalls and network conditions: a filtered port looks the same as a slow host (timeout).
- Fixed 1 s connection timeout and up to 100 concurrent connections; very large ranges on slow networks take time.
- One target at a time; no CIDR ranges or host lists.
- Linux desktop only (tested with X11/Wayland Qt platform plugins).

## License

This project is released under the [MIT License](LICENSE).
