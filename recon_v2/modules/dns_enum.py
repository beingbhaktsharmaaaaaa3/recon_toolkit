import socket
from core.logger import log, section

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.reversename
    import dns.exception
    DNS_LIB = True
except ImportError:
    DNS_LIB = False


class DNSEnumerator:
    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
                    "SRV", "CAA", "DNSKEY", "DS"]

    def __init__(self, target: str):
        self.target = target
        self.results = {}

    def run(self) -> dict:
        section("DNS Enumeration")
        if not DNS_LIB:
            log("WARN", "dnspython not installed — socket fallback (A only)")
            self._socket_fallback()
            return self.results

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        for rtype in self.RECORD_TYPES:
            try:
                answers = resolver.resolve(self.target, rtype)
                records = [str(r) for r in answers]
                self.results[rtype] = records
                for r in records:
                    log("FIND", f"{rtype:<8} → {r}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.exception.Timeout, dns.resolver.NoNameservers):
                pass
            except Exception as e:
                log("WARN", f"{rtype} lookup error: {e}")

        self._reverse_dns()
        self._dnssec_check(resolver)
        self._zone_transfer()
        return self.results

    def _reverse_dns(self):
        """PTR / reverse DNS lookup for resolved IPs."""
        ips = self.results.get("A", []) + self.results.get("AAAA", [])
        ptrs = []
        for ip in ips:
            try:
                rev = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(rev, "PTR")
                for r in answers:
                    ptr = str(r).rstrip(".")
                    ptrs.append({"ip": ip, "ptr": ptr})
                    log("FIND", f"PTR      → {ip} → {ptr}")
            except Exception:
                pass
        if ptrs:
            self.results["PTR"] = ptrs

    def _dnssec_check(self, resolver):
        """Check whether DNSSEC is configured."""
        try:
            resolver.resolve(self.target, "DNSKEY")
            self.results["DNSSEC"] = "enabled"
            log("OK", "DNSSEC enabled")
        except dns.resolver.NoAnswer:
            self.results["DNSSEC"] = "not configured"
            log("WARN", "DNSSEC not configured — susceptible to cache poisoning")
        except Exception:
            pass

    def _zone_transfer(self):
        log("INFO", "Attempting zone transfer (AXFR)…")
        ns_records = self.results.get("NS", [])
        for ns in ns_records:
            ns_host = str(ns).rstrip(".")
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_host, self.target, timeout=5)
                )
                records = [str(n) for n in zone.nodes.keys()]
                self.results["ZONE_TRANSFER"] = {"ns": ns_host, "records": records}
                log("FIND", f"[CRITICAL] Zone transfer SUCCESS on {ns_host}!")
                for name in records:
                    log("FIND", f"  ZT → {name}.{self.target}")
            except Exception:
                log("OK", f"Zone transfer refused by {ns_host}")

    def _socket_fallback(self):
        try:
            ip = socket.gethostbyname(self.target)
            self.results["A"] = [ip]
            log("FIND", f"A → {ip}")
        except socket.gaierror as e:
            log("ERROR", f"DNS resolution failed: {e}")
