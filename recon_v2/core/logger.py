import logging
import sys
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.theme import Theme
    RICH = True
    _theme = Theme({
        "info":  "cyan",
        "ok":    "green",
        "warn":  "yellow",
        "error": "red",
        "find":  "bold magenta",
        "section": "bold blue",
    })
    console = Console(theme=_theme, highlight=False)
except ImportError:
    RICH = False
    console = None


_file_logger = logging.getLogger("recon")
_file_logger.setLevel(logging.DEBUG)
_file_logger.propagate = False

ICONS = {"INFO": "[*]", "OK": "[+]", "WARN": "[!]", "ERROR": "[-]", "FIND": "[>>]"}
STYLES = {"INFO": "info", "OK": "ok", "WARN": "warn", "ERROR": "error", "FIND": "find"}


def setup_file_logger(path: str):
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s"))
    _file_logger.addHandler(fh)


def log(level: str, msg: str):
    icon = ICONS.get(level, "[?]")
    plain = f"  {icon} {msg}"
    _file_logger.info(plain)
    if RICH and console:
        style = STYLES.get(level, "")
        console.print(f"  {icon} {msg}", style=style)
    else:
        print(plain)


def section(title: str):
    _file_logger.info(f"{'─'*20} {title} {'─'*20}")
    if RICH and console:
        console.rule(f"[section] {title} [/section]")
    else:
        print(f"\n{'─'*20} {title} {'─'*20}")


def print_banner():
    lines = [
        "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗",
        "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║",
        "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║",
        "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║",
        "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║",
        "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
        "  Recon & Enumeration Toolkit v2.0  |  Pentesting Edition",
    ]
    if RICH and console:
        from rich.panel import Panel
        from rich.text import Text
        t = Text()
        colors = ["bold red"] * 2 + ["bold yellow"] * 2 + ["bold green"] * 2 + ["dim white"]
        for line, color in zip(lines, colors):
            t.append(line + "\n", style=color)
        console.print(Panel(t, border_style="bold blue", padding=(0, 2)))
    else:
        print("\n" + "\n".join(lines) + "\n")
