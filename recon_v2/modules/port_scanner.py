import concurrent.futures
import random
import socket
import subprocess
import re
import time
from typing import Optional
from core.logger import log, section
from utils.validators import resolve_target

TOP_TCP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1723: "PPTP", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    9200: "Elasticsearch", 27017: "MongoDB",
}

TOP_UDP_PORTS = {
    53:  "DNS",
    67:  "DHCP",
    69:  "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-Trap",
    500: "IKE/IPSec",
    514: "Syslog",
    520: "RIP",
    1194: "OpenVPN",
    1900: "UPnP",
    4500: "IPSec-NAT",
    5353: "mDNS",
}

# SNMP community string probe
SNMP_GET = (
    b"\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63"
    b"\xa0\x19\x02\x04\x71\x68\x61\x1f\x02\x01\x00\x02\x01"
    b"\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
)


class PortScanner:
    def __init__(self, target: str, tcp_ports: Optional[list] = None,
                 udp_ports: Optional[list] = None,
                 threads: int = 100, timeout: float = 1.0,
                 use_nmap: bool = False,
                 stealth: bool = False,
                 delay: float = 0.0,
                 random_delay: bool = False):
        self.target = target
        self.tcp_ports = tcp_ports or list(TOP_TCP_PORTS.keys())
        self.udp_ports = udp_ports
        self.threads = threads
        self.timeout = timeout
        self.use_nmap = use_nmap
        self.stealth = stealth
        self.delay = delay
        self.random_delay = random_delay
        self.results = {"open_tcp": {}, "open_udp": {}, "nmap": None}

        ip, err = resolve_target(target)
        if err:
            log("ERROR", err)
            self.ip = target
        else:
            self.ip = ip

    # ── stealth helpers ───────────────────────────────────────────────────────

    def _sleep(self):
        if self.random_delay:
            time.sleep(random.uniform(0.1, 1.5))
        elif self.delay:
            time.sleep(self.delay)
        elif self.stealth:
            time.sleep(random.uniform(0.3, 1.0))

    # ── TCP ───────────────────────────────────────────────────────────────────

    def run(self) -> dict:
        section("Port Scanning")
        log("INFO", f"Target: {self.target} ({self.ip})")

        if self.stealth:
            log("WARN", "Stealth mode ON — randomized delays, reduced threads")
            self.threads = min(self.threads, 20)

        if self.use_nmap and self._nmap_available():
            self._run_nmap()
        else:
            self._run_tcp()

        if self.udp_ports:
            self._run_udp()

        return self.results

    def _scan_tcp(self, port: int) -> Optional[int]:
        self._sleep()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((self.ip, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    def _run_tcp(self):
        if self.stealth:
            # Sequential in stealth mode — avoid burst detection
            open_ports = []
            port_order = list(self.tcp_ports)
            random.shuffle(port_order)
            for port in port_order:
                res = self._scan_tcp(port)
                if res:
                    open_ports.append(res)
        else:
            open_ports = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self._scan_tcp, p): p for p in self.tcp_ports}
                for f in concurrent.futures.as_completed(futures):
                    res = f.result()
                    if res:
                        open_ports.append(res)

        for port in sorted(open_ports):
            svc = self._identify_service(port, "tcp")
            self.results["open_tcp"][port] = {"service": svc, "proto": "tcp"}
            log("FIND", f"TCP {port:<6} OPEN  ({svc})")

        if not open_ports:
            log("INFO", "No open TCP ports found")

    # ── UDP ───────────────────────────────────────────────────────────────────

    def _scan_udp(self, port: int) -> Optional[dict]:
        self._sleep()
        probe = self._udp_probe(port)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(self.timeout * 2)
                s.sendto(probe, (self.ip, port))
                data, _ = s.recvfrom(1024)
                return {"port": port, "response": data[:80].hex()}
        except socket.timeout:
            # No ICMP unreachable = likely open|filtered
            return {"port": port, "response": "open|filtered (no response)"}
        except OSError:
            # ICMP port unreachable = closed
            return None
        except Exception:
            return None

    def _udp_probe(self, port: int) -> bytes:
        probes = {
            53:  b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                 b"\x07version\x04bind\x00\x00\x10\x00\x03",
            123: b"\x1b" + b"\x00" * 47,
            161: SNMP_GET,
        }
        return probes.get(port, b"\x00" * 4)

    def _run_udp(self):
        log("INFO", f"UDP scan: {len(self.udp_ports)} ports")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.threads, 30)) as ex:
            futures = {ex.submit(self._scan_udp, p): p for p in self.udp_ports}
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    port = res["port"]
                    svc = TOP_UDP_PORTS.get(port, "unknown")
                    self.results["open_udp"][port] = {
                        "service": svc, "proto": "udp",
                        "response": res["response"]
                    }
                    log("FIND", f"UDP {port:<6} OPEN  ({svc})  →  {res['response'][:60]}")

        if not self.results["open_udp"]:
            log("INFO", "No open UDP ports found (or all filtered)")

    # ── Service identification ────────────────────────────────────────────────

    def _identify_service(self, port: int, proto: str) -> str:
        """Protocol probing to detect services on non-standard ports."""
        known = (TOP_TCP_PORTS if proto == "tcp" else TOP_UDP_PORTS).get(port)
        if known:
            return known
        # Probe for HTTP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)
                s.connect((self.ip, port))
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(128).decode("utf-8", errors="ignore")
                if "HTTP" in banner:
                    return "HTTP (non-standard)"
                if "SSH" in banner:
                    return "SSH (non-standard)"
                if "220" in banner and "FTP" in banner.upper():
                    return "FTP (non-standard)"
                if banner.startswith("+PONG") or banner.startswith("-ERR"):
                    return "Redis (non-standard)"
        except Exception:
            pass
        return "unknown"

    # ── nmap ─────────────────────────────────────────────────────────────────

    def _nmap_available(self) -> bool:
        try:
            subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            log("WARN", "nmap not found — socket scanner fallback")
            return False

    def _run_nmap(self):
        port_str = ",".join(str(p) for p in self.tcp_ports)
        udp_flags = ["-sU"] if self.udp_ports else []
        timing = ["-T2"] if self.stealth else ["-T4"]
        cmd = ["nmap", "-sV", "-sC", "--open"] + timing + udp_flags + ["-p", port_str, self.ip]
        log("INFO", f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            output = result.stdout
            self.results["nmap"] = output
            for line in output.splitlines():
                m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
                if m:
                    port, proto, svc, ver = int(m.group(1)), m.group(2), m.group(3), m.group(4).strip()
                    key = f"open_{proto}"
                    self.results[key][port] = {"service": svc, "banner": ver, "proto": proto}
                    log("FIND", f"{proto.upper()} {port:<6} OPEN  ({svc}) {ver}")
        except subprocess.TimeoutExpired:
            log("ERROR", "nmap timed out")
        except Exception as e:
            log("ERROR", f"nmap error: {e}")
