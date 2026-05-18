import concurrent.futures
import socket
from typing import Optional
from core.logger import log, section

try:
    import requests
    REQUESTS = True
except ImportError:
    REQUESTS = False

BUILTIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3", "webmail",
    "autodiscover", "autoconfig", "m", "imap", "test", "vpn", "mail2",
    "new", "mysql", "old", "support", "mobile", "mx", "static", "docs",
    "beta", "shop", "sql", "secure", "demo", "cp", "wiki", "web", "media",
    "email", "images", "img", "www2", "intranet", "admin", "portal", "video",
    "sip", "dns", "dev", "staging", "api", "v1", "v2", "cdn", "assets",
    "upload", "remote", "blog", "forum", "store", "app", "apps", "cloud",
    "help", "status", "monitor", "proxy", "backup", "db", "database",
    "gateway", "internal", "jenkins", "gitlab", "git", "jira", "confluence",
    "kibana", "grafana", "prometheus", "vault", "k8s", "docker", "ci", "cd",
    "build", "deploy", "prod", "production", "uat", "qa", "sandbox",
    "preprod", "stage", "edge", "origin", "s3", "files", "mx1", "mx2",
    "smtp2", "relay", "exchange", "owa", "sharepoint", "crm", "erp",
]


class SubdomainEnumerator:
    def __init__(self, target: str, wordlist: Optional[str] = None,
                 threads: int = 50, timeout: float = 3.0,
                 passive: bool = False):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.passive = passive
        self.results = []
        self._seen = set()

        if wordlist:
            try:
                with open(wordlist) as f:
                    self.wordlist = [w.strip() for w in f if w.strip()]
                log("INFO", f"Wordlist loaded: {wordlist} ({len(self.wordlist)} words)")
            except FileNotFoundError:
                log("WARN", f"Wordlist '{wordlist}' not found — using built-in")
                self.wordlist = BUILTIN_WORDLIST
        else:
            self.wordlist = BUILTIN_WORDLIST

    def run(self) -> list:
        section("Subdomain Enumeration")

        if self.passive:
            self._passive_crtsh()
            self._passive_wayback()

        log("INFO", f"Brute-force: {len(self.wordlist)} words against {self.target}")
        self._bruteforce()

        self.results.sort(key=lambda x: x["subdomain"])
        log("OK", f"Total subdomains found: {len(self.results)}")
        return self.results

    # ── Passive: crt.sh ───────────────────────────────────────────────────────

    def _passive_crtsh(self):
        if not REQUESTS:
            log("WARN", "requests not installed — skipping crt.sh passive recon")
            return
        log("INFO", "Querying crt.sh (passive)…")
        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{self.target}&output=json",
                timeout=15, headers={"User-Agent": "ReconToolkit/2.0"}
            )
            entries = r.json()
            found = set()
            for entry in entries:
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{self.target}") or name == self.target:
                        found.add(name)

            for sub in sorted(found):
                self._add_subdomain(sub, source="crt.sh")
            log("OK", f"crt.sh returned {len(found)} certificate entries")
        except Exception as e:
            log("WARN", f"crt.sh query failed: {e}")

    # ── Passive: Wayback Machine ──────────────────────────────────────────────

    def _passive_wayback(self):
        if not REQUESTS:
            return
        log("INFO", "Querying Wayback Machine CDX API (passive)…")
        try:
            r = requests.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{self.target}",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "5000",
                },
                timeout=20,
                headers={"User-Agent": "ReconToolkit/2.0"}
            )
            import re
            found = set()
            for row in r.json()[1:]:  # skip header row
                url = row[0] if row else ""
                m = re.search(r"https?://([^/]+)", url)
                if m:
                    host = m.group(1).lower()
                    if host.endswith(f".{self.target}"):
                        found.add(host)

            for sub in sorted(found):
                self._add_subdomain(sub, source="wayback")
            log("OK", f"Wayback Machine returned {len(found)} unique hosts")
        except Exception as e:
            log("WARN", f"Wayback Machine query failed: {e}")

    # ── Active: brute-force ───────────────────────────────────────────────────

    def _bruteforce(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._resolve, sub): sub for sub in self.wordlist}
            for f in concurrent.futures.as_completed(futures):
                res = f.result()
                if res:
                    self._add_subdomain(res["subdomain"], res["ips"], source="bruteforce")

    def _resolve(self, sub: str) -> Optional[dict]:
        fqdn = f"{sub}.{self.target}"
        if fqdn in self._seen:
            return None
        try:
            ips = list({r[4][0] for r in socket.getaddrinfo(fqdn, None)})
            return {"subdomain": fqdn, "ips": ips}
        except socket.gaierror:
            return None

    def _add_subdomain(self, subdomain: str, ips: list = None, source: str = ""):
        if subdomain in self._seen:
            return
        self._seen.add(subdomain)
        if ips is None:
            try:
                ips = list({r[4][0] for r in socket.getaddrinfo(subdomain, None)})
            except Exception:
                ips = []
        entry = {"subdomain": subdomain, "ips": ips, "source": source}
        self.results.append(entry)
        ip_str = ", ".join(ips) if ips else "unresolved"
        log("FIND", f"[{source:<12}] {subdomain:<45} → {ip_str}")
