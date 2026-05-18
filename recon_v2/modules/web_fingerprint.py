import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from core.logger import log, section

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS = True
except ImportError:
    REQUESTS = False

TECH_SIGNATURES = {
    "WordPress":   {"headers": [],                                  "body": ["wp-content", "wp-includes", "wordpress"]},
    "Drupal":      {"headers": ["X-Generator: Drupal"],             "body": ["Drupal.settings", "/sites/default/"]},
    "Joomla":      {"headers": [],                                  "body": ["/media/jui/", "Joomla!"]},
    "Laravel":     {"headers": ["laravel_session"],                 "body": ["laravel_session", "csrf-token"]},
    "Django":      {"headers": [],                                  "body": ["csrfmiddlewaretoken"]},
    "Rails":       {"headers": ["X-Runtime"],                       "body": ["rails", "authenticity_token"]},
    "React":       {"headers": [],                                  "body": ["react.development.js", "__react", "data-reactroot"]},
    "Angular":     {"headers": [],                                  "body": ["ng-version", "angular.min.js", "ng-app"]},
    "Vue.js":      {"headers": [],                                  "body": ["vue.min.js", "__vue__", "data-v-"]},
    "jQuery":      {"headers": [],                                  "body": ["jquery.min.js", "jquery-"]},
    "Bootstrap":   {"headers": [],                                  "body": ["bootstrap.min.css", "bootstrap.css"]},
    "Next.js":     {"headers": ["x-powered-by: Next.js"],          "body": ["__NEXT_DATA__", "_next/static"]},
    "Nuxt.js":     {"headers": [],                                  "body": ["__nuxt", "__NUXT__"]},
    "Nginx":       {"headers": ["Server: nginx"],                   "body": []},
    "Apache":      {"headers": ["Server: Apache"],                  "body": []},
    "IIS":         {"headers": ["Server: Microsoft-IIS"],           "body": []},
    "Tomcat":      {"headers": ["Server: Apache-Coyote"],           "body": ["Apache Tomcat"]},
    "Spring Boot": {"headers": [],                                  "body": ["Whitelabel Error Page", "spring.boot"]},
    "Cloudflare":  {"headers": ["CF-RAY", "cf-cache-status"],       "body": []},
    "AWS ELB":     {"headers": ["x-amzn-requestid"],                "body": []},
    "AWS CF":      {"headers": ["x-amz-cf-id"],                     "body": []},
    "Fastly":      {"headers": ["X-Served-By", "X-Cache"],          "body": []},
    "PHP":         {"headers": ["X-Powered-By: PHP"],               "body": []},
    "ASP.NET":     {"headers": ["X-Powered-By: ASP.NET",
                                "X-AspNet-Version"],                "body": ["__VIEWSTATE"]},
    "GraphQL":     {"headers": [],                                  "body": ["__typename", "graphql"]},
}

SECURITY_HEADERS = {
    "Strict-Transport-Security":  "HSTS",
    "Content-Security-Policy":    "CSP",
    "X-Frame-Options":            "Clickjacking protection",
    "X-Content-Type-Options":     "MIME sniffing protection",
    "Referrer-Policy":            "Referrer policy",
    "Permissions-Policy":         "Permissions policy",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Resource-Policy": "CORP",
}

LEAK_HEADERS = [
    "X-Powered-By", "Server", "X-AspNet-Version", "X-Generator",
    "X-Drupal-Cache", "X-Varnish", "X-Backend-Server", "X-Forwarded-Host",
    "Via", "X-Debug-Token", "X-Debug-Token-Link",
]


class WebFingerprinter:
    def __init__(self, target: str, ports: Optional[list] = None):
        self.target = target
        self.ports = ports or [80, 443, 8080, 8443]
        self.results = {}

    def run(self) -> dict:
        section("Web Fingerprinting")
        if not REQUESTS:
            log("WARN", "requests not installed — skipping web fingerprinting")
            return self.results

        for port in self.ports:
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{self.target}:{port}"
            self._fingerprint(url)

        return self.results

    def _fingerprint(self, url: str):
        try:
            r = requests.get(
                url, timeout=10, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (ReconToolkit/2.0)"}
            )
        except requests.exceptions.ConnectionError:
            log("INFO", f"{url}  →  connection refused")
            return
        except requests.exceptions.Timeout:
            log("WARN", f"{url}  →  timed out")
            return
        except requests.exceptions.SSLError:
            log("WARN", f"{url}  →  SSL error (self-signed cert?)")
            return
        except Exception as e:
            log("ERROR", f"{url}  →  {e}")
            return

        log("OK", f"{url}  →  HTTP {r.status_code}  ({len(r.content)} bytes)")

        info = {
            "url": url,
            "final_url": r.url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "technologies": self._detect_tech(r),
            "missing_security_headers": [],
            "present_security_headers": {},
            "info_leaking_headers": {},
            "cookies": self._audit_cookies(r),
            "title": "",
            "ssl": None,
            "robots_txt": None,
            "sitemap": None,
        }

        # Page title
        m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
        if m:
            info["title"] = m.group(1).strip()[:120]
            log("INFO", f"  Title: {info['title']}")

        # Technologies
        if info["technologies"]:
            log("FIND", f"  Technologies: {', '.join(info['technologies'])}")

        # Security headers
        for hdr, label in SECURITY_HEADERS.items():
            if hdr in r.headers:
                info["present_security_headers"][hdr] = r.headers[hdr]
                log("OK", f"  {label}: {r.headers[hdr][:80]}")
            else:
                info["missing_security_headers"].append(label)
        if info["missing_security_headers"]:
            log("WARN", f"  Missing security headers: {', '.join(info['missing_security_headers'])}")

        # Info-leaking headers
        for hdr in LEAK_HEADERS:
            if hdr in r.headers:
                info["info_leaking_headers"][hdr] = r.headers[hdr]
                log("FIND", f"  [Info-Leak] {hdr}: {r.headers[hdr]}")

        # SSL/TLS analysis
        if r.url.startswith("https"):
            info["ssl"] = self._tls_analysis(self.target,
                int(r.url.split(":")[2].split("/")[0]) if ":" in r.url.split("//")[1] else 443)

        # robots.txt
        info["robots_txt"] = self._fetch_path(r.url, "/robots.txt")
        if info["robots_txt"]:
            log("FIND", f"  robots.txt found ({len(info['robots_txt'])} bytes)")
            disallowed = [l for l in info["robots_txt"].splitlines() if l.lower().startswith("disallow")]
            for line in disallowed[:10]:
                log("INFO", f"    {line}")

        # sitemap.xml
        info["sitemap"] = self._fetch_path(r.url, "/sitemap.xml")
        if info["sitemap"]:
            log("FIND", f"  sitemap.xml found ({len(info['sitemap'])} bytes)")

        self.results[url] = info

    # ── SSL/TLS analysis ──────────────────────────────────────────────────────

    def _tls_analysis(self, host: str, port: int) -> dict:
        result = {}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    result["tls_version"] = version
                    result["cipher"] = cipher[0] if cipher else "unknown"
                    result["key_bits"] = cipher[2] if cipher else None

                    # Cert details
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    result["subject_cn"] = subject.get("commonName", "")
                    result["issuer"]     = issuer.get("organizationName", "")
                    result["not_before"] = cert.get("notBefore", "")
                    result["not_after"]  = cert.get("notAfter", "")

                    # SANs
                    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                    result["san"] = sans

                    # Expiry check
                    try:
                        expiry = datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.now(timezone.utc)).days
                        result["days_until_expiry"] = days_left
                        if days_left < 0:
                            log("FIND", f"  [CRITICAL] TLS cert EXPIRED {abs(days_left)} days ago!")
                        elif days_left < 30:
                            log("WARN", f"  TLS cert expires in {days_left} days")
                        else:
                            log("OK", f"  TLS cert valid for {days_left} days | {version} | {result['cipher']}")
                    except ValueError:
                        pass

                    # Weak cipher / version warnings
                    if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        log("FIND", f"  [HIGH] Weak TLS version: {version}")
                    if "RC4" in result["cipher"] or "DES" in result["cipher"] or "NULL" in result["cipher"]:
                        log("FIND", f"  [HIGH] Weak cipher: {result['cipher']}")
                    if result["key_bits"] and result["key_bits"] < 128:
                        log("FIND", f"  [HIGH] Weak key size: {result['key_bits']} bits")

        except Exception as e:
            result["error"] = str(e)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _fetch_path(self, base_url: str, path: str) -> Optional[str]:
        try:
            url = "/".join(base_url.rstrip("/").split("/")[:3]) + path
            r = requests.get(url, timeout=6, verify=False,
                             headers={"User-Agent": "Mozilla/5.0 (ReconToolkit/2.0)"})
            if r.status_code == 200 and len(r.text) > 10:
                return r.text[:5000]
        except Exception:
            pass
        return None

    def _detect_tech(self, response) -> list:
        header_str = " ".join(f"{k}: {v}" for k, v in response.headers.items())
        cookie_str = " ".join(response.cookies.keys())
        body = response.text[:60000]
        detected = []
        for tech, sigs in TECH_SIGNATURES.items():
            hit = False
            for hdr in sigs["headers"]:
                if hdr.lower() in header_str.lower() or hdr.lower() in cookie_str.lower():
                    hit = True
                    break
            if not hit:
                for sig in sigs["body"]:
                    if sig.lower() in body.lower():
                        hit = True
                        break
            if hit:
                detected.append(tech)
        return list(dict.fromkeys(detected))

    def _audit_cookies(self, response) -> dict:
        cookies = {}
        for cookie in response.cookies:
            flags = []
            # Correctly check cookie attributes (not value string)
            if not cookie.secure:
                flags.append("missing-Secure")
            if not cookie.has_nonstandard_attr("HttpOnly") and \
               "httponly" not in str(cookie._rest).lower():
                flags.append("missing-HttpOnly")
            if not cookie.has_nonstandard_attr("SameSite") and \
               "samesite" not in str(cookie._rest).lower():
                flags.append("missing-SameSite")

            cookies[cookie.name] = {
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "flags": flags,
            }
            if flags:
                log("WARN", f"  Cookie '{cookie.name}': {', '.join(flags)}")
        return cookies
