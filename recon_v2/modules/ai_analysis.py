import json
import os
import re
from core.logger import log, section

try:
    import anthropic
    ANTHROPIC_LIB = True
except ImportError:
    ANTHROPIC_LIB = False

MODEL = "claude-opus-4-6"

SYSTEM_PROMPT = """You are a senior penetration tester and security analyst with 15 years of experience.
Analyze the recon findings below and respond ONLY with valid JSON — no markdown, no preamble, no explanation outside the JSON.
Use this exact structure:
{
  "executive_summary": "2-3 sentence plain-English summary of the overall security posture and most urgent risks",
  "risk_score": 72,
  "risk_level": "HIGH",
  "attack_surface_summary": "1-2 sentences describing what an attacker sees from the outside",
  "critical_findings": [
    {
      "title": "Short finding title",
      "explanation": "What this means, why it is dangerous, real-world impact",
      "remediation": "Specific, actionable fix steps",
      "severity": "CRITICAL"
    }
  ],
  "remediation_roadmap": [
    {"priority": 1, "action": "Exact action to take", "timeframe": "24 hours"},
    {"priority": 2, "action": "Exact action to take", "timeframe": "1 week"},
    {"priority": 3, "action": "Exact action to take", "timeframe": "1 month"}
  ],
  "attack_vectors": [
    "Short description of a realistic attack path an adversary could follow"
  ],
  "recon_suggestions": [
    "Next recon step the tester should try based on what was found"
  ]
}
Rules:
- risk_score is 0-100 (100 = most critical, 0 = clean)
- risk_level is one of: CRITICAL / HIGH / MEDIUM / LOW / INFO
- severity in critical_findings is one of: CRITICAL / HIGH / MEDIUM / LOW
- Minimum 3 critical_findings if any open ports or CVEs exist
- Minimum 3 remediation_roadmap items
- Minimum 2 attack_vectors
- Minimum 3 recon_suggestions
- Be specific — reference actual ports, CVE IDs, service names from the data"""


class AIAnalyzer:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.enabled = bool(self.api_key) and ANTHROPIC_LIB

    # ── public ────────────────────────────────────────────────────────────────

    def run(self, target: str, findings: dict) -> dict:
        section("AI Analysis")

        if not ANTHROPIC_LIB:
            log("WARN", "anthropic package not installed")
            log("INFO", "Run: pip install anthropic")
            return self._disabled("anthropic package not installed — run: pip install anthropic")

        if not self.api_key:
            log("WARN", "ANTHROPIC_API_KEY not set — AI features disabled")
            log("INFO", "Get a free key at https://console.anthropic.com")
            log("INFO", "Then run: export ANTHROPIC_API_KEY=sk-ant-...")
            return self._disabled("ANTHROPIC_API_KEY not set. Get a free key at https://console.anthropic.com then run: export ANTHROPIC_API_KEY=sk-ant-...")

        prompt = self._build_prompt(target, findings)
        log("INFO", f"Sending {len(prompt)} chars of findings to Claude ({MODEL})…")

        try:
            client   = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=MODEL,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw    = response.content[0].text
            result = self._parse(raw)
            log("OK",   f"AI analysis complete — risk score: {result.get('risk_score', '?')}/100  [{result.get('risk_level', '?')}]")
            log("FIND", f"Executive summary: {result.get('executive_summary','')[:120]}…")
            return result

        except anthropic.AuthenticationError:
            log("ERROR", "Invalid ANTHROPIC_API_KEY — check your key at https://console.anthropic.com")
            return self._disabled("Invalid API key")
        except anthropic.RateLimitError:
            log("ERROR", "Anthropic rate limit hit — wait a moment and retry with --ai")
            return self._disabled("Rate limit hit — retry later")
        except Exception as e:
            log("ERROR", f"AI analysis failed: {e}")
            return self._disabled(str(e))

    # ── prompt builder ────────────────────────────────────────────────────────

    def _build_prompt(self, target: str, findings: dict) -> str:
        ports    = findings.get("ports", {})
        open_tcp = ports.get("open_tcp", {})
        open_udp = ports.get("open_udp", {})
        dns      = findings.get("dns", {})
        subs     = findings.get("subdomains", [])
        web      = findings.get("web", {})
        banners  = findings.get("banners", {})
        whois_d  = findings.get("whois", {})

        cves, techs, missing_hdrs, ssl_issues, cookie_issues = [], [], [], [], []

        for port, bdata in banners.items():
            for cve in bdata.get("cves", []):
                cves.append(f"  Port {port}: {cve['id']} — {cve['description']}")

        for url, udata in web.items():
            techs.extend(udata.get("technologies", []))
            missing_hdrs.extend(udata.get("missing_security_headers", []))
            ssl = udata.get("ssl") or {}
            days = ssl.get("days_until_expiry")
            ver  = ssl.get("tls_version", "")
            if isinstance(days, int) and days < 30:
                ssl_issues.append(f"Certificate expiring in {days} days on {url}")
            if ver in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                ssl_issues.append(f"Weak TLS {ver} on {url}")
            for name, cd in udata.get("cookies", {}).items():
                flags = cd.get("flags", [])
                if flags:
                    cookie_issues.append(f"{name} on {url}: {', '.join(flags)}")

        lines = [
            f"TARGET: {target}",
            "",
            f"OPEN TCP PORTS ({len(open_tcp)}): {', '.join(str(p) for p in sorted(open_tcp.keys())) or 'none'}",
        ]
        for p, info in sorted(open_tcp.items()):
            banner = info.get("banner", "")
            lines.append(f"  {p}/tcp  {info.get('service','unknown')}  {banner[:80]}")

        lines.append(f"\nOPEN UDP PORTS ({len(open_udp)}): {', '.join(str(p) for p in sorted(open_udp.keys())) or 'none'}")
        for p, info in sorted(open_udp.items()):
            lines.append(f"  {p}/udp  {info.get('service','unknown')}")

        zt = dns.get("ZONE_TRANSFER")
        lines += [
            f"\nDNS RECORD TYPES: {', '.join(k for k in dns if k not in ('ZONE_TRANSFER','PTR','DNSSEC'))}",
            f"ZONE TRANSFER: {'SUCCESSFUL — FULL DNS EXPOSED' if zt else 'refused (good)'}",
            f"DNSSEC: {dns.get('DNSSEC', 'unknown')}",
            f"\nSUBDOMAINS FOUND ({len(subs)}):",
        ]
        for s in subs[:15]:
            lines.append(f"  {s['subdomain']} → {', '.join(s.get('ips',[]))}")
        if len(subs) > 15:
            lines.append(f"  … and {len(subs)-15} more")

        lines += [
            f"\nWEB TECHNOLOGIES DETECTED: {', '.join(set(techs)) or 'none'}",
            f"MISSING SECURITY HEADERS: {', '.join(set(missing_hdrs)) or 'none'}",
            f"COOKIE ISSUES: {'; '.join(cookie_issues) or 'none'}",
            f"SSL/TLS ISSUES: {'; '.join(ssl_issues) or 'none'}",
        ]

        if cves:
            lines.append(f"\nCVE HINTS MATCHED ({len(cves)}):")
            lines.extend(cves)
        else:
            lines.append("\nCVE HINTS MATCHED: none")

        if whois_d:
            lines.append(f"\nWHOIS: registrar={whois_d.get('registrar','?')} org={whois_d.get('org','?')} country={whois_d.get('country','?')}")

        return "\n".join(lines)

    # ── response parser ───────────────────────────────────────────────────────

    def _parse(self, raw: str) -> dict:
        raw = raw.strip()
        # Strip markdown code fences if Claude added them
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1].lstrip("json").strip() if len(parts) > 1 else raw
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            m = re.search(r"\{.*\}", raw, re.DOTALL)
            if m:
                try:
                    return json.loads(m.group())
                except Exception:
                    pass
            log("WARN", "AI response was not valid JSON — using empty result")
            return self._disabled("Response parse error")

    # ── empty result ──────────────────────────────────────────────────────────

    @staticmethod
    def _disabled(reason: str) -> dict:
        return {
            "_disabled": True,
            "_reason": reason,
            "executive_summary": "",
            "risk_score": 0,
            "risk_level": "",
            "attack_surface_summary": "",
            "critical_findings": [],
            "remediation_roadmap": [],
            "attack_vectors": [],
            "recon_suggestions": [],
        }
