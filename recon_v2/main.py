#!/usr/bin/env python3
"""
Recon & Enumeration Toolkit v2.0
Usage: python3 main.py -t <target> [options]
       python3 main.py --config config.yaml
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# ── Make sure package root is on the path when run directly ──────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.logger import log, section, print_banner, setup_file_logger
from utils.validators import (
    validate_target, validate_target_strict,
    parse_ports, validate_threads, validate_timeout,
    resolve_target,
)
from modules.dns_enum      import DNSEnumerator
from modules.port_scanner  import PortScanner, TOP_TCP_PORTS, TOP_UDP_PORTS
from modules.subdomain     import SubdomainEnumerator
from modules.web_fingerprint import WebFingerprinter
from modules.whois_lookup  import WHOISLookup
from modules.banner_grab   import BannerGrabber
from modules.ai_analysis   import AIAnalyzer
from reports.generator     import ReportGenerator

try:
    import yaml
    YAML = True
except ImportError:
    YAML = False


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIG FILE LOADER
# ═══════════════════════════════════════════════════════════════════════════════

def load_config(path: str) -> dict:
    if not YAML:
        log("WARN", "pyyaml not installed — cannot load config file (pip install pyyaml)")
        return {}
    try:
        with open(path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        log("ERROR", f"Config file not found: {path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        log("ERROR", f"Config file parse error: {e}")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# CHECKPOINT (RESUME) SUPPORT
# ═══════════════════════════════════════════════════════════════════════════════

def save_checkpoint(path: str, findings: dict, completed: list):
    state = {"completed_modules": completed, "findings": findings}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, default=str)
    log("INFO", f"Checkpoint saved → {path}")


def load_checkpoint(path: str) -> tuple[dict, list]:
    try:
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
        completed = state.get("completed_modules", [])
        findings  = state.get("findings", {})
        log("OK", f"Resuming from checkpoint: {path}")
        log("INFO", f"  Completed modules: {', '.join(completed)}")
        return findings, completed
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log("ERROR", f"Cannot load checkpoint: {e}")
        sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        prog="recon_toolkit",
        description="Recon & Enumeration Toolkit v2.0 — Pentesting Engagement Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py -t example.com
  python3 main.py -t 192.168.1.1 --modules ports banners --ports 1-65535 --threads 300
  python3 main.py -t example.com --stealth --random-delay --modules dns subs web
  python3 main.py -t example.com --passive --wordlist /opt/SecLists/Discovery/DNS/top5000.txt
  python3 main.py -t example.com --udp --nmap -o ./reports/client
  python3 main.py --config config.yaml
  python3 main.py -t example.com --resume ./scan_state.json
        """
    )

    # Target
    p.add_argument("-t", "--target", default=None,
                   help="Hostname, IP, or URL (required unless --config sets it)")
    p.add_argument("--config", default=None,
                   help="Path to YAML config file (CLI flags override config values)")

    # Modules
    p.add_argument("--modules", nargs="+",
                   choices=["dns", "ports", "subs", "web", "whois", "banners"],
                   help="Modules to run (default: all)")

    # Port scanning
    p.add_argument("--ports", default=None,
                   help="Port range or list: '1-1024' or '80,443,8080'")
    p.add_argument("--nmap", action="store_true",
                   help="Use nmap with -sV -sC (requires nmap in PATH)")
    p.add_argument("--udp", action="store_true",
                   help="Also scan common UDP ports (53,67,123,161,500…)")

    # Subdomain
    p.add_argument("--wordlist", default=None,
                   help="Path to subdomain wordlist file")
    p.add_argument("--passive", action="store_true",
                   help="Enable passive recon (crt.sh, Wayback Machine) before brute-force")

    # Stealth / evasion
    p.add_argument("--stealth", action="store_true",
                   help="Stealth mode: reduced threads (≤20), randomized jitter")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Fixed delay in seconds between probes (e.g. 0.5)")
    p.add_argument("--random-delay", action="store_true",
                   help="Random delay 0.1–1.5s between every probe")

    # Performance
    p.add_argument("--threads", type=int, default=100,
                   help="Concurrent threads (default: 100, max: 1000)")
    p.add_argument("--timeout", type=float, default=1.5,
                   help="Socket timeout in seconds (default: 1.5)")

    # AI
    p.add_argument("--ai", action="store_true",
                   help="Enable AI analysis (requires ANTHROPIC_API_KEY env var)")
    p.add_argument("--api-key", default=None,
                   help="Anthropic API key (or set ANTHROPIC_API_KEY env var)")

    # Output
    p.add_argument("-o", "--output", default=None,
                   help="Base path for HTML report (e.g. -o ./reports/client → client.html)")
    p.add_argument("--logfile", default=None,
                   help="Path to write log file (e.g. ./recon.log)")
    p.add_argument("--no-banner", action="store_true",
                   help="Suppress ASCII banner")

    # Resume
    p.add_argument("--resume", default=None,
                   help="Path to a checkpoint file to resume an interrupted scan")

    return p.parse_args()


# ═══════════════════════════════════════════════════════════════════════════════
# MERGE CONFIG + ARGS (CLI wins)
# ═══════════════════════════════════════════════════════════════════════════════

def build_config(args) -> dict:
    cfg = {}
    if args.config:
        cfg = load_config(args.config)

    # CLI overrides config
    def _get(cli_val, cfg_key, default=None):
        return cli_val if cli_val not in (None, False, 0, 0.0) else cfg.get(cfg_key, default)

    return {
        "target":       args.target or cfg.get("target"),
        "modules":      args.modules or cfg.get("modules",
                        ["dns", "ports", "subs", "web", "whois", "banners"]),
        "ports":        args.ports or cfg.get("ports"),
        "nmap":         args.nmap or cfg.get("use_nmap", False),
        "udp":          args.udp or cfg.get("scan_udp", False),
        "wordlist":     args.wordlist or cfg.get("wordlist"),
        "passive":      args.passive or cfg.get("passive", False),
        "stealth":      args.stealth or cfg.get("stealth", False),
        "delay":        args.delay or cfg.get("delay", 0.0),
        "random_delay": args.random_delay or cfg.get("random_delay", False),
        "threads":      args.threads if args.threads != 100 else cfg.get("threads", 100),
        "timeout":      args.timeout if args.timeout != 1.5 else cfg.get("timeout", 1.5),
        "ai":           args.ai or cfg.get("ai_enabled", False),
        "api_key":      args.api_key or cfg.get("anthropic_api_key"),
        "output":       args.output or cfg.get("output"),
        "logfile":      args.logfile or cfg.get("logfile"),
        "no_banner":    args.no_banner,
        "resume":       args.resume,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════

def validate_config(cfg: dict) -> bool:
    ok = True

    if not cfg["target"]:
        log("ERROR", "No target specified. Use -t <target> or set 'target' in config.yaml")
        ok = False

    valid, err = validate_threads(cfg["threads"])
    if not valid:
        log("ERROR", f"--threads: {err}")
        ok = False

    valid, err = validate_timeout(cfg["timeout"])
    if not valid:
        log("ERROR", f"--timeout: {err}")
        ok = False

    if cfg["ports"]:
        ports, err = parse_ports(cfg["ports"])
        if err:
            log("ERROR", f"--ports: {err}")
            ok = False

    return ok


# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT PATH BUILDER
# ═══════════════════════════════════════════════════════════════════════════════

def build_output_base(cfg: dict) -> str:
    if cfg["output"]:
        os.makedirs(os.path.dirname(os.path.abspath(cfg["output"])), exist_ok=True)
        return cfg["output"]
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe = cfg["target"].replace(".", "_").replace("/", "_").replace(":", "_")
    base = f"recon_{safe}_{ts}"
    return base


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    args = parse_args()
    cfg  = build_config(args)

    if not cfg["no_banner"]:
        print_banner()

    if cfg["logfile"]:
        setup_file_logger(cfg["logfile"])
        log("INFO", f"Logging to file: {cfg['logfile']}")

    log("WARN", "⚠  Authorized use only. Ensure you have written permission before scanning.")

    if not validate_config(cfg):
        sys.exit(1)

    target = validate_target(cfg["target"])
    ok, err = validate_target_strict(target)
    if not ok:
        log("ERROR", err)
        sys.exit(1)

    scan_time  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    out_base   = build_output_base(cfg)
    checkpoint = out_base + "_state.json"

    # Determine port list
    if cfg["ports"]:
        tcp_port_list, _ = parse_ports(cfg["ports"])
    else:
        tcp_port_list = list(TOP_TCP_PORTS.keys())

    udp_port_list = list(TOP_UDP_PORTS.keys()) if cfg["udp"] else None

    modules = cfg["modules"]

    log("INFO", f"Target   : {target}")
    log("INFO", f"Modules  : {', '.join(modules)}")
    if cfg["stealth"]:
        log("WARN", "Stealth mode ENABLED — slow, quiet scan")
    if cfg["passive"]:
        log("INFO", "Passive recon ENABLED (crt.sh, Wayback Machine)")

    # ── Resume from checkpoint ───────────────────────────────────────────────
    if cfg["resume"]:
        findings, completed = load_checkpoint(cfg["resume"])
        modules = [m for m in modules if m not in completed]
        log("INFO", f"Skipping completed: {', '.join(completed)}")
        log("INFO", f"Remaining modules: {', '.join(modules)}")
    else:
        findings   = {}
        completed  = []

    # ── Run modules with workflow chaining ───────────────────────────────────

    # 1. DNS
    if "dns" in modules:
        findings["dns"] = DNSEnumerator(target).run()
        completed.append("dns")
        save_checkpoint(checkpoint, findings, completed)

    # 2. WHOIS
    if "whois" in modules:
        findings["whois"] = WHOISLookup(target).run()
        completed.append("whois")
        save_checkpoint(checkpoint, findings, completed)

    # 3. PORT SCAN
    if "ports" in modules:
        findings["ports"] = PortScanner(
            target,
            tcp_ports=tcp_port_list,
            udp_ports=udp_port_list,
            threads=cfg["threads"],
            timeout=cfg["timeout"],
            use_nmap=cfg["nmap"],
            stealth=cfg["stealth"],
            delay=cfg["delay"],
            random_delay=cfg["random_delay"],
        ).run()
        completed.append("ports")
        save_checkpoint(checkpoint, findings, completed)

    # 4. BANNER GRABBING — chained from port results
    if "banners" in modules:
        open_tcp = findings.get("ports", {}).get("open_tcp", {})
        open_udp = findings.get("ports", {}).get("open_udp", {})
        findings["banners"] = BannerGrabber(target, open_tcp, open_udp).run()
        completed.append("banners")
        save_checkpoint(checkpoint, findings, completed)

    # 5. SUBDOMAIN ENUMERATION (passive first, then brute-force)
    if "subs" in modules:
        findings["subdomains"] = SubdomainEnumerator(
            target,
            wordlist=cfg["wordlist"],
            threads=cfg["threads"],
            timeout=cfg["timeout"],
            passive=cfg["passive"],
        ).run()
        completed.append("subs")
        save_checkpoint(checkpoint, findings, completed)

    # 6. WEB FINGERPRINTING — chained: auto-detect web ports from port scan,
    #    also scans subdomains that were discovered
    if "web" in modules:
        open_tcp = findings.get("ports", {}).get("open_tcp", {})
        web_ports = [p for p in open_tcp if p in (80, 443, 8080, 8443, 8000, 8888)] \
                    or [80, 443]
        findings["web"] = WebFingerprinter(target, web_ports).run()

        # Chain: also fingerprint discovered subdomains (first 5 to avoid noise)
        subs = findings.get("subdomains", [])[:5]
        for sub in subs:
            sub_host = sub["subdomain"]
            sub_results = WebFingerprinter(sub_host, [80, 443]).run()
            findings["web"].update(sub_results)

        completed.append("web")
        save_checkpoint(checkpoint, findings, completed)

    # ── AI analysis (after all modules — uses full findings) ──────────────────
    if cfg["ai"]:
        findings["ai"] = AIAnalyzer(api_key=cfg.get("api_key")).run(target, findings)
    else:
        log("INFO", "AI analysis skipped — add --ai flag to enable")
        findings["ai"] = {
            "_disabled": True,
            "_reason": "Run with --ai flag to enable. Requires ANTHROPIC_API_KEY env var."
        }

    # ── Reports ───────────────────────────────────────────────────────────────
    reporter = ReportGenerator(target, scan_time, findings)
    reporter.print_summary()
    reporter.save_html(out_base + ".html")

    # Clean up checkpoint on successful full scan
    if set(completed) >= set(cfg["modules"]):
        try:
            os.remove(checkpoint)
        except FileNotFoundError:
            pass

    log("OK", f"HTML report saved → {out_base}.html")
    log("OK", "Scan complete.")


if __name__ == "__main__":
    main()
