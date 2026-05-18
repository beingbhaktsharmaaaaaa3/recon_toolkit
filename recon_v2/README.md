# 🔍 Recon & Enumeration Toolkit v2.0

> A modular, automated recon and enumeration framework for professional pentesting engagements.
> Outputs a clean **dark-theme HTML report** after every scan — open it in any browser.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-purple?style=flat-square)

---

## ⚠️ Legal Disclaimer

> **This tool is for authorized penetration testing and security research only.**
> Only run this against systems you have explicit written permission to test.
> The tool prints this warning on every launch. The authors accept no liability for misuse.

---

## 📋 Table of Contents

- [Features](#-features)
- [Project Structure](#-project-structure)
- [Step 1 — Install Python](#-step-1--install-python)
- [Step 2 — Set up the environment](#-step-2--set-up-the-environment)
- [Step 3 — Run your first scan](#-step-3--run-your-first-scan)
- [All Flags](#-all-flags)
- [Modules](#-modules)
- [Common Scan Recipes](#-common-scan-recipes)
- [Stealth Mode](#-stealth-mode)
- [Passive Recon](#-passive-recon)
- [Resume an Interrupted Scan](#-resume-an-interrupted-scan)
- [Config File](#-config-file)
- [HTML Report](#-html-report)
- [Troubleshooting](#-troubleshooting-every-common-error)
- [Contributing](#-contributing)

---

## ✨ Features

| Module | What it does |
|--------|-------------|
| **DNS enumeration** | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA · PTR/reverse DNS · DNSSEC check · AXFR zone transfer |
| **Port scanner** | Multi-threaded TCP + optional UDP · socket-based or nmap · stealth mode · detects services on non-standard ports |
| **Subdomain brute-force** | Concurrent wordlist enumeration · passive crt.sh + Wayback Machine sources |
| **Web fingerprinting** | 25+ tech signatures · security header audit · SSL/TLS analysis · cookie flags · robots.txt · sitemap |
| **WHOIS lookup** | Registrar · org · dates · emails · ASN · socket fallback if library missing |
| **Banner grabbing** | Service-specific probes (FTP, SSH, SMTP, Redis…) · CVE hint matching on 25+ vulnerable version strings |
| **HTML report** | Dark-theme report with stats grid, open ports, CVE hints, subdomains, tech stack, endpoint details |

---

## 📁 Project Structure

```
recon_v2/
├── main.py                  ← Run this file
├── config.yaml              ← Optional config (edit once, reuse forever)
├── requirements.txt         ← Python packages to install
│
├── core/
│   ├── __init__.py
│   └── logger.py
│
├── modules/
│   ├── __init__.py
│   ├── dns_enum.py
│   ├── port_scanner.py
│   ├── subdomain.py
│   ├── web_fingerprint.py
│   ├── whois_lookup.py
│   └── banner_grab.py
│
├── reports/
│   ├── __init__.py
│   └── generator.py
│
└── utils/
    ├── __init__.py
    └── validators.py
```

---

## 🐍 Step 1 — Install Python

You need **Python 3.8 or higher**.

```bash
# Check your version
python3 --version
```

If Python is not installed:

```bash
# Kali / Ubuntu / Debian
sudo apt update && sudo apt install python3 python3-pip python3-venv

# macOS
brew install python3

# Windows — download from https://python.org/downloads
# During install, check "Add Python to PATH"
```

---

## ⚙️ Step 2 — Set up the environment

### Option A — Virtual environment (recommended, prevents all import errors)

```bash
# 1. Go into the project folder
cd recon_v2

# 2. Create the virtual environment
python3 -m venv venv

# 3. Activate it
#    Kali / Linux / macOS:
source venv/bin/activate

#    Windows Command Prompt:
venv\Scripts\activate.bat

#    Windows PowerShell:
venv\Scripts\Activate.ps1

# 4. Install all dependencies
pip install -r requirements.txt

# You're ready. Your terminal prompt will now show (venv)
```

> **Every time you come back**, just activate the venv again (step 3) before running.
> To stop using the venv: `deactivate`

---

### Option B — Install directly (simpler, but may conflict with system packages)

```bash
cd recon_v2
pip install -r requirements.txt
```

---

### Fix permissions (Kali Linux — do this once)

If you get `PermissionError` when running the tool, the folder was created by root. Fix it:

```bash
# Replace 'kali' with your actual username if different
sudo chown -R kali:kali ~/pen_Tools/
sudo chmod -R 755 ~/pen_Tools/
```

---

### Install nmap (optional — only needed for `--nmap` flag)

```bash
# Kali / Debian / Ubuntu
sudo apt install nmap

# macOS
brew install nmap

# Windows — https://nmap.org/download.html
```

---

## 🚀 Step 3 — Run your first scan

```bash
# Make sure venv is active first (you'll see "(venv)" in your prompt)
source venv/bin/activate

# Run a full scan against an IP
python3 main.py -t 10.10.10.22

# Run a full scan against a domain
python3 main.py -t example.com

# Run against a URL (scheme is stripped automatically)
python3 main.py -t https://example.com
```

After the scan finishes, an **HTML report** is saved in the same folder.
Open it in any browser — double-click the `.html` file.

---

## 🚩 All Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-t / --target` | — | **Required.** Hostname, IP address, or URL |
| `--config` | — | Path to YAML config file |
| `--modules` | all | Which modules to run (space-separated) |
| `--ports` | top 30 | Port range `1-1024` or list `80,443,8080` |
| `--nmap` | off | Use nmap for port scanning (must be installed) |
| `--udp` | off | Also scan common UDP ports |
| `--wordlist` | built-in | Path to a subdomain wordlist file |
| `--passive` | off | Passive recon via crt.sh and Wayback Machine |
| `--stealth` | off | Slow, quiet scan — ≤20 threads + random delays |
| `--delay` | `0.0` | Fixed delay in seconds between probes |
| `--random-delay` | off | Random 0.1–1.5s delay between each probe |
| `--threads` | `100` | Number of concurrent threads (max 1000) |
| `--timeout` | `1.5` | Socket timeout in seconds |
| `-o / --output` | auto | Base path for HTML report |
| `--logfile` | — | Also write log to this file |
| `--no-banner` | off | Hide the ASCII banner |
| `--resume` | — | Resume from a checkpoint file |

---

## 🔬 Modules

Run specific modules with `--modules`:

```bash
python3 main.py -t example.com --modules dns ports
```

Available modules:

| Name | What it does |
|------|-------------|
| `dns` | DNS records + PTR + DNSSEC + zone transfer |
| `ports` | TCP (and optionally UDP) port scanning |
| `subs` | Subdomain brute-force (+ passive with `--passive`) |
| `web` | Web fingerprinting, headers, SSL/TLS, cookies |
| `whois` | WHOIS lookup (domain or IP) |
| `banners` | Service banner grabbing + CVE hints |

---

## 🍳 Common Scan Recipes

### Full scan — IP address

```bash
python3 main.py -t 10.10.10.22
```

### Full scan — domain with custom report location

```bash
python3 main.py -t example.com -o ./reports/client_name
# saves: ./reports/client_name.html
```

### Full port range scan

```bash
python3 main.py -t 10.10.10.22 --ports 1-65535 --threads 300
```

### Full port range with nmap (better service detection)

```bash
python3 main.py -t example.com --ports 1-65535 --nmap
```

### TCP + UDP scan

```bash
python3 main.py -t example.com --udp
```

### DNS + subdomains only

```bash
python3 main.py -t example.com --modules dns subs
```

### Subdomain hunt with large wordlist

```bash
python3 main.py -t example.com --modules subs \
  --wordlist /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Passive subdomain recon (no brute-force noise)

```bash
python3 main.py -t example.com --passive --modules subs
```

### Web fingerprint only

```bash
python3 main.py -t example.com --modules web
```

### Stealth scan (slow, avoids IDS/WAF triggers)

```bash
python3 main.py -t example.com --stealth --random-delay
```

### Save a log file alongside the HTML report

```bash
python3 main.py -t example.com --logfile ./recon.log
```

---

## 🥷 Stealth Mode

Default scanning is aggressive (100 threads, no delays) and may trigger IDS or WAF alerts.

```bash
# Auto stealth — caps threads at 20, adds 0.3–1.0s random jitter, randomizes port order
python3 main.py -t example.com --stealth

# Fixed delay between every probe
python3 main.py -t example.com --delay 0.5

# Random delay 0.1–1.5s per probe
python3 main.py -t example.com --random-delay

# Maximum stealth — combine all three
python3 main.py -t example.com --stealth --delay 0.3 --random-delay
```

---

## 🕵️ Passive Recon

`--passive` queries external APIs before active scanning. No probes are sent to the target during this phase.

```bash
python3 main.py -t example.com --passive --modules subs
```

Sources used:
- **crt.sh** — TLS certificate transparency logs (finds subdomains from issued certs)
- **Wayback Machine CDX API** — archived URLs exposing historical subdomains

Results are merged with active brute-force and deduplicated.

---

## ♻️ Resume an Interrupted Scan

A checkpoint file (`_state.json`) is saved automatically after each module. If the scan is interrupted (Ctrl+C, power cut, etc.):

```bash
# Resume from where it stopped
python3 main.py -t example.com --resume recon_example_com_TIMESTAMP_state.json
```

The checkpoint file is deleted automatically on successful completion.

---

## ⚙️ Config File

Edit `config.yaml` once and stop typing flags every time:

```yaml
# config.yaml
modules: [dns, ports, subs, web, whois, banners]
threads: 150
timeout: 2.0
stealth: false
passive: false
scan_udp: false
use_nmap: false
wordlist: /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
logfile: ./logs/recon.log
```

```bash
python3 main.py --config config.yaml -t example.com
```

CLI flags always override config file values.

---

## 📄 HTML Report

Every scan produces one `.html` file. Open it in any browser.

```
recon_10_10_10_22_20240510_143022.html   ← auto-named
client_name.html                          ← when you use -o ./client_name
```

The report includes:
- Stats grid — open ports, subdomains found, CVE hints, missing security headers
- DNS records table
- Open TCP and UDP ports
- CVE hints from banner grabbing
- Subdomains with IPs and discovery source
- Detected technologies
- Web endpoint breakdown — status, title, SSL/TLS, missing headers, cookies
- WHOIS data

---

## 🛠️ Troubleshooting — Every Common Error

---

### `PermissionError: [Errno 13] Permission denied`

The tool cannot write the HTML report or checkpoint file to the folder.

```bash
# Fix folder ownership (replace 'kali' with your username)
sudo chown -R kali:kali ~/pen_Tools/
sudo chmod -R 755 ~/pen_Tools/

# Then run WITHOUT sudo
python3 main.py -t 10.10.10.22
```

---

### `ModuleNotFoundError: No module named 'dns'`

The Python packages are not installed.

```bash
pip install -r requirements.txt

# If that doesn't work, your pip is pointing to the wrong Python:
python3 -m pip install -r requirements.txt
```

---

### Packages install but tool still gives `ModuleNotFoundError`

You have multiple Python environments installed. Use a virtual environment to isolate everything:

```bash
python3 -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate.bat      # Windows CMD
pip install -r requirements.txt
python3 main.py -t example.com
```

---

### `DeprecationWarning: datetime.datetime.utcnow() is deprecated`

This warning appeared in v2.0 and is **fixed in the current version**. If you still see it, you are running an old copy of the files. Download the latest zip and replace your files.

---

### `pip: command not found`

```bash
# Kali / Debian / Ubuntu
sudo apt install python3-pip

# macOS
brew install python3            # pip is included

# Any platform
python3 -m ensurepip --upgrade
```

---

### `Permission denied: ./main.py`

```bash
chmod +x main.py
# Or always run it as:
python3 main.py -t example.com
```

---

### Windows PowerShell blocks venv activation

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
venv\Scripts\Activate.ps1
```

---

### Scan is very slow

```bash
# Increase threads
python3 main.py -t example.com --threads 300

# Reduce port range
python3 main.py -t example.com --ports 1-1024

# Increase timeout for slow/remote targets
python3 main.py -t example.com --timeout 3.0
```

---

### `OSError: [Errno 24] Too many open files`

Too many threads are opening sockets at once.

```bash
# Reduce threads
python3 main.py -t example.com --threads 50

# Or raise the OS file descriptor limit temporarily
ulimit -n 4096
```

---

### SSL errors during web fingerprinting

```bash
pip install --upgrade requests urllib3
```

---

### nmap not found after installing

```bash
which nmap          # should print a path
nmap --version      # should print version info
```

On Windows, ensure nmap's install directory is in your system PATH environment variable.

---

### `--config` flag does nothing

pyyaml is not installed:

```bash
pip install pyyaml
```

---

### HTML report is empty or missing

Check whether the scan completed. If it was interrupted, use `--resume`:

```bash
ls recon_*_state.json                   # find the checkpoint
python3 main.py -t TARGET --resume recon_TARGET_TIMESTAMP_state.json
```

---

### `ModuleNotFoundError: No module named 'core'`

You are not running from inside the `recon_v2/` folder.

```bash
cd recon_v2
python3 main.py -t example.com
```

---

## 🤝 Contributing

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-improvement`
3. Commit: `git commit -m "Add HTTP directory brute-force module"`
4. Push: `git push origin feature/my-improvement`
5. Open a Pull Request

**Ideas for new modules:**
- HTTP directory / file brute-force
- Screenshot capture (Playwright)
- asyncio rewrite for higher throughput
- SMB / SMTP enumeration
- Shodan / Censys API integration
- Full CVE database integration (NVD API)

---

## 📜 License

MIT License — free to use, modify, and distribute with attribution.

---

*Built for security professionals. Use responsibly and legally.*
