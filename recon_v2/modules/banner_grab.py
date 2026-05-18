import socket
import time
from core.logger import log, section

# Known vulnerable version strings mapped to CVE hints.
# Format: (substring_to_match_lowercase, CVE_id, description)
CVE_HINTS = [
    ("openssh 7.2",       "CVE-2016-6210",  "OpenSSH 7.2 user enumeration"),
    ("openssh 6.",        "CVE-2016-0777",  "OpenSSH <6.9 roaming information leak"),
    ("openssh 5.",        "CVE-2010-4478",  "OpenSSH <5.6 J-PAKE bypass"),
    ("apache/2.4.49",     "CVE-2021-41773", "Apache 2.4.49 path traversal / RCE"),
    ("apache/2.4.50",     "CVE-2021-42013", "Apache 2.4.50 path traversal RCE"),
    ("apache/2.2.",       "CVE-2017-7679",  "Apache 2.2.x mod_mime buffer overread"),
    ("nginx/1.3.",        "CVE-2013-2028",  "Nginx 1.3.x stack overflow"),
    ("nginx/1.9.5",       "CVE-2016-0742",  "Nginx invalid pointer dereference"),
    ("iis/6.0",           "CVE-2017-7269",  "IIS 6.0 WebDAV buffer overflow (WannaCry era)"),
    ("iis/7.5",           "CVE-2015-1635",  "IIS 7.5 HTTP.sys remote code execution"),
    ("vsftpd 2.3.4",      "CVE-2011-2523",  "vsftpd 2.3.4 backdoor command execution"),
    ("proftpd 1.3.3",     "CVE-2010-4221",  "ProFTPD 1.3.3 sreplace buffer overflow"),
    ("exim 4.",           "CVE-2019-10149", "Exim <4.92 remote command execution"),
    ("sendmail 8.12",     "CVE-2003-0161",  "Sendmail 8.12 prescan buffer overflow"),
    ("ms-ftp",            "CVE-2009-3023",  "IIS FTP 7.0/7.5 stack overflow"),
    ("filezilla server 0.9.4", "CVE-2006-6565", "FileZilla FTP server DoS"),
    ("redis",             "CVE-2022-0543",  "Redis Lua sandbox escape (check version)"),
    ("mysql 5.1",         "CVE-2012-2122",  "MySQL 5.1 authentication bypass"),
    ("mysql 5.5",         "CVE-2016-6662",  "MySQL 5.5 privilege escalation"),
    ("postgresql 9.",     "CVE-2019-9193",  "PostgreSQL 9.x COPY TO/FROM PROGRAM RCE"),
    ("mongodb 2.",        "CVE-2013-4650",  "MongoDB 2.x auth bypass"),
    ("openssl/1.0.1",     "CVE-2014-0160",  "Heartbleed — OpenSSL 1.0.1 memory leak"),
    ("openssl/1.0.2",     "CVE-2016-0800",  "DROWN attack — OpenSSL 1.0.2 SSLv2"),
    ("php/5.",            "CVE-2019-11043",  "PHP 7/5 FPM RCE via nginx (check exact ver)"),
    ("php/7.1",           "CVE-2019-11043",  "PHP 7.1 FPM RCE via nginx"),
    ("tomcat/9.0.0",      "CVE-2019-0232",   "Tomcat 9.0.0 CGI enableCmdLineArguments RCE"),
    ("tomcat/7.",         "CVE-2017-12617",  "Tomcat 7 JSP upload bypass RCE"),
    ("jboss",             "CVE-2017-12149",  "JBoss deserialisation RCE"),
    ("weblogic",          "CVE-2020-14882",  "Oracle WebLogic console RCE"),
    ("wp-login",          "CVE-2017-1001000", "WordPress REST API content injection"),
    ("drupal",            "CVE-2018-7600",   "Drupalgeddon2 RCE"),
]

# Service-specific probes sent after connecting
PROBES = {
    21:    b"",                                  # wait for banner
    22:    b"",                                  # wait for banner
    25:    b"EHLO recon.test\r\n",
    80:    b"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    110:   b"",
    143:   b"",
    443:   None,                                 # skip raw TLS
    3306:  b"",
    5432:  b"",
    6379:  b"PING\r\n",
    9200:  b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    27017: None,
}


class BannerGrabber:
    def __init__(self, target: str, open_tcp: dict, open_udp: dict = None):
        self.target = target
        self.open_tcp = open_tcp
        self.open_udp = open_udp or {}
        self.results = {}
        try:
            self.ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.ip = target

    def run(self) -> dict:
        section("Banner Grabbing")
        all_ports = {**self.open_tcp, **self.open_udp}
        if not all_ports:
            log("INFO", "No open ports — skipping banner grabbing")
            return self.results

        for port in sorted(all_ports.keys()):
            probe = PROBES.get(port, b"\r\n")
            if probe is None:
                continue
            banner = self._grab(port, probe)
            if banner:
                cves = self._match_cves(banner)
                self.results[port] = {"banner": banner, "cves": cves}
                log("FIND", f"Port {port:<6} → {banner[:100]}")
                for cve in cves:
                    log("WARN", f"         [!] {cve['id']} — {cve['description']}")

        if not self.results:
            log("INFO", "No banners retrieved")
        return self.results

    def _grab(self, port: int, probe: bytes, timeout: float = 3.0) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((self.ip, port))
                if probe:
                    p = probe.replace(b"{host}", self.target.encode())
                    s.sendall(p)
                time.sleep(0.4)
                data = s.recv(2048).decode("utf-8", errors="ignore").strip()
            return data.replace("\n", " ").replace("\r", "")[:300]
        except Exception:
            return ""

    def _match_cves(self, banner: str) -> list:
        matches = []
        banner_lower = banner.lower()
        for substring, cve_id, description in CVE_HINTS:
            if substring in banner_lower:
                matches.append({"id": cve_id, "description": description})
        return matches
