import socket
from core.logger import log, section

try:
    import whois
    WHOIS_LIB = True
except ImportError:
    WHOIS_LIB = False


class WHOISLookup:
    def __init__(self, target: str):
        self.target = target
        self.results = {}

    def run(self) -> dict:
        section("WHOIS Lookup")
        if WHOIS_LIB:
            self._lib_whois()
        else:
            log("WARN", "python-whois not installed — using socket fallback")
            self._socket_whois()
        return self.results

    def _lib_whois(self):
        try:
            w = whois.whois(self.target)
            fields = {
                "registrar":       w.registrar,
                "creation_date":   w.creation_date,
                "expiration_date": w.expiration_date,
                "updated_date":    w.updated_date,
                "name_servers":    w.name_servers,
                "org":             w.org,
                "country":         w.country,
                "emails":          w.emails,
                "dnssec":          w.dnssec,
                "status":          w.status,
            }
            for key, val in fields.items():
                if val is None:
                    continue
                # Flatten lists to first element for display, keep full for storage
                display = val[0] if isinstance(val, list) else val
                self.results[key] = str(val)
                log("INFO", f"  {key:<20} {str(display)[:80]}")
        except Exception as e:
            log("WARN", f"python-whois failed: {e} — trying socket fallback")
            self._socket_whois()

    def _socket_whois(self):
        """
        Two-stage raw WHOIS:
        1. Query whois.iana.org to find the authoritative WHOIS server.
        2. Query that server directly.
        """
        try:
            # Stage 1: get refer server
            raw_iana = self._query_whois_server("whois.iana.org", self.target)
            refer_server = None
            for line in raw_iana.splitlines():
                if line.lower().startswith("refer:"):
                    refer_server = line.split(":", 1)[1].strip()
                    break

            # Stage 2: query the refer server (or fall back to iana output)
            if refer_server:
                raw = self._query_whois_server(refer_server, self.target)
            else:
                raw = raw_iana

            self.results["raw"] = raw[:3000]
            # Print first 30 non-empty lines
            count = 0
            for line in raw.splitlines():
                line = line.strip()
                if line and not line.startswith("%") and not line.startswith("#"):
                    log("INFO", f"  {line}")
                    count += 1
                    if count >= 30:
                        break
        except Exception as e:
            log("ERROR", f"Socket WHOIS failed: {e}")

    def _query_whois_server(self, server: str, query: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((server, 43))
            s.sendall((query + "\r\n").encode())
            chunks = []
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="ignore")
