# ⚡ VolTrx - Website Traffic & Access Log Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20|%20macOS%20|%20Windows-lightgrey.svg)]()

**VolTrx** is a lightweight, zero-dependency Python tool for analyzing web server traffic, parsing access logs (Nginx / Apache), and conducting live website endpoint performance monitoring.

---

## ✨ Features

- 📊 **Web Server Log Analysis**: Parses Nginx and Apache Combined Log Format into actionable metrics.
- 👥 **Visitor Insights**: Tracks unique client IPs, top visiting user agents, and referral sources.
- 🌐 **HTTP Health Metrics**: Categorizes traffic by response status codes (`2xx`, `3xx`, `4xx`, `5xx`).
- 🚨 **Security Anomaly Detection**: Flags common probes (path traversal, sensitive file scans like `.env`/`.git`, and SQLi/XSS keywords).
- ⏱️ **Live Endpoint Monitor**: Probes target URLs to measure real-time latency, uptime percentage, and server headers.
- 📑 **Visual HTML & JSON Export**: Generates clean, dark-mode standalone HTML dashboards and JSON summaries.
- 📦 **Zero External Dependencies**: Works out-of-the-box with standard Python libraries.

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/BenSnn/VolTrx.git
cd VolTrx
```

### 2. Run the instant interactive demo
```bash
python main.py demo
```
This generates a sample web access log, analyzes the traffic distribution, detects suspicious requests, and produces `traffic_report.html` and `traffic_report.json`.

---

## 🛠️ Usage Guide

### 1. Analyzing Web Server Access Logs
Analyze an existing access log file and generate a visual HTML report:
```bash
python main.py parse /var/log/nginx/access.log --html report.html --json report.json
```

Output:
```text
==================================================
 [*] TRAFFIC OVERVIEW
==================================================
 Total Requests    : 10,480
 Unique Visitors   : 3,210
 Bandwidth Served  : 142.5 MB
 Security Alerts   : 14

--------------------------------------------------
 [*] HTTP STATUS CATEGORIES
--------------------------------------------------
 2xx (Success)        :   9,420 ( 89.9%) | ###########################
 3xx (Redirect)       :     610 (  5.8%) | #
 4xx (Client Error)   :     420 (  4.0%) | #
 5xx (Server Error)   :      30 (  0.3%) | 
```

### 2. Live Website Performance & Traffic Monitoring
Probe a live website endpoint to analyze response times and availability:
```bash
python main.py monitor https://example.com --count 10 --interval 1.0
```

---

## 📂 Project Architecture

```text
VolTrx/
├── main.py                  # Entrypoint runner
├── voltrx/
│   ├── __init__.py          # Package initialization
│   ├── analyzer.py          # Log parsing & anomaly detection engine
│   ├── monitor.py           # Real-time HTTP endpoint monitor
│   ├── reporter.py          # HTML & JSON dashboard generator
│   └── cli.py               # Terminal interface and subcommands
├── sample_access.log        # Sample web access log
└── README.md                # Documentation
```

---

## 👥 Contributors

- **Lead Developer**: [@BenSnn](https://github.com/BenSnn)
- **Collaborator**: [@RobsHs](https://github.com/RobsHs)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
