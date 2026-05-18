from datetime import datetime, timezone
from core.logger import log, section


class ReportGenerator:
    def __init__(self, target: str, scan_time: str, findings: dict):
        self.target    = target
        self.scan_time = scan_time
        self.findings  = findings
        self.generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # ─────────────────────────────────────────────────────────────────────────
    def save_html(self, path: str):
        dns     = self.findings.get("dns", {})
        ports   = self.findings.get("ports", {})
        subs    = self.findings.get("subdomains", [])
        web     = self.findings.get("web", {})
        whois_d = self.findings.get("whois", {})
        banners = self.findings.get("banners", {})
        open_tcp = ports.get("open_tcp", {})
        open_udp = ports.get("open_udp", {})
        all_techs, missing_headers, cve_hits = [], [], []
        for url_data in web.values():
            all_techs.extend(url_data.get("technologies", []))
            missing_headers.extend(url_data.get("missing_security_headers", []))
        for port, bdata in banners.items():
            for cve in bdata.get("cves", []):
                cve_hits.append((port, cve["id"], cve["description"]))

        cve_warn   = "warn" if cve_hits else ""
        mhdr_warn  = "warn" if missing_headers else ""
        sub0       = subs[0]["subdomain"] if subs else "—"
        tech0      = ", ".join(list(set(all_techs))[:3]) or "—"
        cve0       = cve_hits[0][1] if cve_hits else "clean"
        mhdr0      = list(set(missing_headers))[0] if missing_headers else "all present"
        tcp_ports  = ", ".join(str(p) for p in sorted(list(open_tcp.keys())[:5]))
        udp_ports  = ", ".join(str(p) for p in sorted(list(open_udp.keys())[:5])) or "none"

        html = (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '<meta charset="UTF-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1.0">\n'
            f"<title>RECON :: {self._esc(self.target)}</title>\n"
            "<style>\n"
            ":root{"
            "--g:#00ff41;--gd:#00cc33;--gx:rgba(0,255,65,.07);--gb:rgba(0,255,65,.18);"
            "--gm:rgba(0,255,65,.5);--bg:#090909;--bg2:#0f0f0f;--bg3:#141414;"
            "--bd:rgba(0,255,65,.13);--bdb:rgba(0,255,65,.26);"
            "--txt:rgba(0,255,65,.72);--dim:rgba(0,255,65,.32);"
            "--red:#ff4444;--rdb:rgba(255,68,68,.11);--rdbr:rgba(255,68,68,.24);"
            "--ylw:#ffd700;--ylb:rgba(255,215,0,.11);--blu:#4fc3f7;--blb:rgba(79,195,247,.09);"
            "--sw:242px}"
            "*{box-sizing:border-box;margin:0;padding:0}"
            "html{scroll-behavior:smooth}"
            "body{background:var(--bg);color:var(--g);font-family:'Courier New',Courier,monospace;font-size:13px;display:flex;min-height:100vh}"
            "::-webkit-scrollbar{width:4px;height:4px}"
            "::-webkit-scrollbar-track{background:var(--bg)}"
            "::-webkit-scrollbar-thumb{background:var(--bd);border-radius:2px}"
            "#sidebar{position:fixed;top:0;left:0;bottom:0;width:var(--sw);background:var(--bg2);border-right:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden;z-index:100}"
            ".sb-hd{padding:18px 18px 14px;border-bottom:1px solid var(--bd)}"
            ".sb-logo{font-size:21px;font-weight:700;letter-spacing:.13em;color:var(--g)}"
            ".sb-logo span{color:var(--dim)}"
            ".sb-target{font-size:11px;color:var(--dim);margin-top:5px;word-break:break-all;line-height:1.4}"
            ".sb-time{font-size:9px;color:var(--dim);margin-top:3px;opacity:.6}"
            ".sb-stats{padding:12px 14px;border-bottom:1px solid var(--bd);display:grid;grid-template-columns:1fr 1fr;gap:7px}"
            ".sb-stat{background:var(--gx);border:1px solid var(--bd);border-radius:4px;padding:6px 8px;text-align:center}"
            ".sb-stat .n{font-size:17px;font-weight:700;color:var(--g);line-height:1}"
            ".sb-stat .l{font-size:9px;color:var(--dim);margin-top:3px;text-transform:uppercase;letter-spacing:.06em}"
            ".sb-nav{flex:1;overflow-y:auto;padding:8px 0}"
            ".sb-nav::-webkit-scrollbar{width:2px}"
            ".nav-grp{padding:10px 14px 3px;font-size:9px;color:var(--dim);letter-spacing:.1em;text-transform:uppercase}"
            ".nav-a{display:flex;align-items:center;gap:8px;padding:6px 14px;font-size:12px;color:var(--txt);text-decoration:none;border-left:2px solid transparent;transition:all .1s}"
            ".nav-a:hover{color:var(--g);background:var(--gx);border-left-color:var(--gm)}"
            ".nav-a.active{color:var(--g);background:var(--gx);border-left-color:var(--g)}"
            ".nav-a .ic{width:22px;font-size:11px;color:var(--dim);flex-shrink:0;font-style:normal}"
            ".nb{margin-left:auto;background:var(--gb);color:var(--g);font-size:9px;padding:1px 6px;border-radius:10px;min-width:18px;text-align:center}"
            ".nb.w{background:var(--rdb);color:var(--red)}"
            ".sb-ft{padding:10px 14px;border-top:1px solid var(--bd);font-size:9px;color:var(--dim);line-height:1.7}"
            "#topbar{position:fixed;top:0;left:var(--sw);right:0;height:34px;background:rgba(9,9,9,.94);border-bottom:1px solid var(--bd);display:flex;align-items:center;padding:0 32px;gap:14px;z-index:50;backdrop-filter:blur(4px)}"
            ".tb-dot{width:7px;height:7px;border-radius:50%;background:var(--g);flex-shrink:0;animation:blink 1.8s infinite}"
            "@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}"
            ".tb-i{font-size:10px;color:var(--dim);letter-spacing:.05em;white-space:nowrap}"
            "#main{margin-left:var(--sw);flex:1;padding:62px 34px 40px;max-width:920px}"
            ".sec{margin-bottom:38px}"
            ".sec-hd{display:flex;align-items:center;gap:9px;margin-bottom:14px;padding-bottom:9px;border-bottom:1px solid var(--bd)}"
            ".sec-ic{font-size:13px;color:var(--dim)}"
            ".sec-title{font-size:14px;font-weight:700;color:var(--g);letter-spacing:.09em;text-transform:uppercase}"
            ".sec-ct{font-size:10px;color:var(--dim);margin-left:auto}"
            ".stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:28px}"
            ".sc{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;padding:14px 15px;position:relative;overflow:hidden}"
            ".sc::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--g)}"
            ".sc.w::before{background:var(--red)}"
            ".sc.i::before{background:var(--blu)}"
            ".sc .num{font-size:27px;font-weight:700;color:var(--g);line-height:1}"
            ".sc.w .num{color:var(--red)}"
            ".sc.i .num{color:var(--blu)}"
            ".sc .lbl{font-size:10px;color:var(--dim);margin-top:5px;text-transform:uppercase;letter-spacing:.06em}"
            ".sc .sub{font-size:10px;color:var(--dim);margin-top:4px;opacity:.55;word-break:break-all}"
            ".tw{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;overflow:hidden}"
            ".tw.danger{border-color:rgba(255,68,68,.22)}"
            "table{width:100%;border-collapse:collapse;font-size:12px}"
            "thead th{text-align:left;font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;padding:6px 12px;border-bottom:1px solid var(--bd);background:var(--bg3)}"
            "tbody td{padding:7px 12px;border-bottom:1px solid rgba(0,255,65,.05);color:var(--txt);vertical-align:middle;word-break:break-word}"
            "tbody tr:last-child td{border-bottom:none}"
            "tbody tr:hover td{background:var(--gx)}"
            ".bg{display:inline-block;font-size:10px;padding:2px 8px;border-radius:3px;font-weight:700;letter-spacing:.03em;white-space:nowrap}"
            ".bg-g{background:var(--gx);color:var(--g);border:1px solid var(--bd)}"
            ".bg-r{background:var(--rdb);color:var(--red);border:1px solid var(--rdbr)}"
            ".bg-y{background:var(--ylb);color:var(--ylw);border:1px solid rgba(255,215,0,.2)}"
            ".bg-b{background:var(--blb);color:var(--blu);border:1px solid rgba(79,195,247,.2)}"
            ".bg-d{background:rgba(255,255,255,.04);color:var(--dim);border:1px solid var(--bd)}"
            ".pb{display:flex;align-items:center;gap:8px}"
            ".pf{height:3px;background:var(--g);border-radius:2px;opacity:.65;min-width:3px}"
            ".tag{background:var(--gx);border:1px solid var(--bd);color:var(--txt);font-size:11px;padding:3px 9px;border-radius:3px;display:inline-block}"
            ".tag-wrap{display:flex;flex-wrap:wrap;gap:5px}"
            ".cr{display:flex;align-items:flex-start;gap:11px;padding:9px 13px;border-bottom:1px solid rgba(255,68,68,.07)}"
            ".cr:last-child{border-bottom:none}"
            ".cr .id{font-size:11px;font-weight:700;color:var(--red);min-width:130px;flex-shrink:0}"
            ".cr .pt{font-size:10px;color:var(--dim);min-width:50px;flex-shrink:0;margin-top:1px}"
            ".cr .ds{font-size:12px;color:var(--txt);line-height:1.5}"
            ".kv{display:grid;grid-template-columns:155px 1fr}"
            ".kv-r:hover .kk,.kv-r:hover .kv{background:var(--gx)}"
            ".kk{padding:7px 12px;font-size:10px;color:var(--dim);border-bottom:1px solid rgba(0,255,65,.05);text-transform:uppercase;letter-spacing:.05em}"
            ".kv{padding:7px 12px;font-size:12px;color:var(--txt);border-bottom:1px solid rgba(0,255,65,.05);word-break:break-all}"
            ".src-c{background:rgba(79,195,247,.09);color:var(--blu);border:1px solid rgba(79,195,247,.2);font-size:9px;padding:1px 6px;border-radius:3px}"
            ".src-b{background:var(--gx);color:var(--dim);border:1px solid var(--bd);font-size:9px;padding:1px 6px;border-radius:3px}"
            ".src-w{background:var(--ylb);color:var(--ylw);border:1px solid rgba(255,215,0,.2);font-size:9px;padding:1px 6px;border-radius:3px}"
            ".ep{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;margin-bottom:12px;overflow:hidden}"
            ".ep-hd{display:flex;align-items:center;gap:8px;padding:9px 13px;background:var(--bg3);border-bottom:1px solid var(--bd);flex-wrap:wrap}"
            ".ep-url{font-size:13px;color:var(--g);font-weight:700;word-break:break-all}"
            ".ep-sts{font-size:11px;flex-shrink:0}"
            ".ep-ttl{font-size:11px;color:var(--txt);font-style:italic;flex:1;min-width:100px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}"
            ".ep-sec{padding:8px 13px;border-bottom:1px solid rgba(0,255,65,.05)}"
            ".ep-sec:last-child{border-bottom:none}"
            ".ep-lbl{font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:5px}"
            ".wt{background:var(--rdb);color:var(--red);border:1px solid var(--rdbr);font-size:10px;padding:2px 7px;border-radius:3px;display:inline-block;margin:2px}"
            ".ot{background:var(--gx);color:var(--gd);border:1px solid var(--bd);font-size:10px;padding:2px 7px;border-radius:3px;display:inline-block;margin:2px}"
            ".empty{padding:18px;text-align:center;color:var(--dim);font-size:12px}"
            "@media print{#sidebar,#topbar{display:none}#main{margin-left:0;padding-top:20px}}"
            ".ai-disabled{background:var(--bg2);border:1px dashed var(--bd);border-radius:6px;padding:20px;text-align:center;color:var(--dim);font-size:12px}"
            ".ai-disabled code{background:var(--bg3);padding:2px 6px;border-radius:3px;color:var(--txt);font-size:11px}"
            ".risk-wrap{display:flex;align-items:center;gap:24px;margin-bottom:20px}"
            ".risk-gauge{position:relative;width:100px;height:100px;flex-shrink:0}"
            ".risk-gauge svg{width:100px;height:100px}"
            ".risk-num{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}"
            ".risk-num .rn{font-size:22px;font-weight:700;color:var(--g);line-height:1}"
            ".risk-num .rl{font-size:9px;color:var(--dim);letter-spacing:.07em;margin-top:2px}"
            ".risk-num .rn.rc{color:var(--red)}.risk-num .rn.rh{color:#ff8c00}.risk-num .rn.rm{color:var(--ylw)}.risk-num .rn.ri{color:var(--blu)}"
            ".risk-info{flex:1}"
            ".risk-level-badge{display:inline-block;font-size:11px;font-weight:700;padding:3px 10px;border-radius:3px;margin-bottom:8px;letter-spacing:.05em}"
            ".rlb-c{background:var(--rdb);color:var(--red);border:1px solid rgba(255,68,68,.3)}"
            ".rlb-h{background:rgba(255,140,0,.1);color:#ff8c00;border:1px solid rgba(255,140,0,.25)}"
            ".rlb-m{background:var(--ylb);color:var(--ylw);border:1px solid rgba(255,215,0,.25)}"
            ".rlb-l{background:var(--gx);color:var(--gd);border:1px solid var(--bd)}"
            ".rlb-i{background:var(--blb);color:var(--blu);border:1px solid rgba(79,195,247,.25)}"
            ".exec-sum{font-size:13px;color:var(--txt);line-height:1.7}"
            ".atk-sum{font-size:12px;color:var(--dim);margin-top:8px;line-height:1.6}"
            ".ai-card{background:var(--bg2);border:1px solid var(--bd);border-radius:6px;padding:14px 16px;margin-bottom:10px}"
            ".ai-card-title{font-size:12px;font-weight:700;color:var(--g);margin-bottom:6px;letter-spacing:.05em}"
            ".ai-card-body{font-size:12px;color:var(--txt);line-height:1.6}"
            ".ai-card-fix{font-size:11px;color:var(--dim);margin-top:6px;line-height:1.5;border-top:1px solid var(--bd);padding-top:6px}"
            ".ai-card-fix::before{content:'FIX: ';color:var(--gd);font-weight:700}"
            ".road-row{display:flex;align-items:flex-start;gap:12px;padding:8px 0;border-bottom:1px solid rgba(0,255,65,.05)}"
            ".road-row:last-child{border-bottom:none}"
            ".road-pri{width:22px;height:22px;border-radius:50%;background:var(--gx);border:1px solid var(--bd);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:var(--g);flex-shrink:0;margin-top:1px}"
            ".road-act{font-size:12px;color:var(--txt);flex:1}"
            ".road-tf{font-size:10px;color:var(--dim);white-space:nowrap}"
            ".vec-item{display:flex;align-items:flex-start;gap:8px;padding:5px 0;font-size:12px;color:var(--txt);border-bottom:1px solid rgba(0,255,65,.04)}"
            ".vec-item:last-child{border-bottom:none}"
            ".vec-arrow{color:var(--red);flex-shrink:0;font-weight:700}"
            ".sug-item{display:flex;align-items:flex-start;gap:8px;padding:5px 0;font-size:12px;color:var(--txt);border-bottom:1px solid rgba(0,255,65,.04)}"
            ".sug-item:last-child{border-bottom:none}"
            ".sug-arrow{color:var(--blu);flex-shrink:0}"
            ".ai-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}"
            "\n</style>\n</head>\n<body>\n"
        )

        # Sidebar
        html += (
            '<nav id="sidebar">\n'
            f'<div class="sb-hd"><div class="sb-logo">RE<span>//</span>CON</div>'
            f'<div class="sb-target">&gt;&nbsp;{self._esc(self.target)}</div>'
            f'<div class="sb-time">{self._esc(self.scan_time)}</div></div>\n'
            '<div class="sb-stats">'
            f'<div class="sb-stat"><div class="n">{len(open_tcp)}</div><div class="l">TCP</div></div>'
            f'<div class="sb-stat"><div class="n">{len(open_udp)}</div><div class="l">UDP</div></div>'
            f'<div class="sb-stat"><div class="n">{len(subs)}</div><div class="l">Subs</div></div>'
            f'<div class="sb-stat"><div class="n">{len(cve_hits)}</div><div class="l">CVEs</div></div>'
            '</div>\n'
            '<div class="sb-nav">'
            '<div class="nav-grp">modules</div>'
            '<a class="nav-link nav-a" href="#ai"><i class="ic">[AI]</i>AI Analysis</a>'
            f'<a class="nav-link nav-a" href="#overview"><i class="ic">[*]</i>Overview<span class="nb">{len(open_tcp)+len(open_udp)}</span></a>'
            f'<a class="nav-link nav-a" href="#dns"><i class="ic">[D]</i>DNS Records<span class="nb">{len(dns)}</span></a>'
            f'<a class="nav-link nav-a" href="#ports"><i class="ic">[P]</i>Open Ports<span class="nb">{len(open_tcp)+len(open_udp)}</span></a>'
            f'<a class="nav-link nav-a" href="#banners"><i class="ic">[B]</i>Banners<span class="nb">{len(banners)}</span></a>'
            f'<a class="nav-link nav-a" href="#subs"><i class="ic">[S]</i>Subdomains<span class="nb">{len(subs)}</span></a>'
            f'<a class="nav-link nav-a" href="#web"><i class="ic">[W]</i>Web Recon<span class="nb">{len(web)}</span></a>'
            f'<a class="nav-link nav-a" href="#cve"><i class="ic">[!]</i>CVE Alerts<span class="nb {cve_warn}">{len(cve_hits)}</span></a>'
            '<a class="nav-link nav-a" href="#whois"><i class="ic">[Q]</i>WHOIS</a>'
            '</div>\n'
            f'<div class="sb-ft">Recon &amp; Enumeration Toolkit v2.0<br>Generated: {self._esc(self.generated)}<br>Authorized use only.</div>'
            '</nav>\n'
        )

        # Topbar
        html += (
            '<div id="topbar">'
            '<div class="tb-dot"></div>'
            f'<span class="tb-i">TARGET :: {self._esc(self.target)}</span>'
            '<span class="tb-i">|</span>'
            f'<span class="tb-i">TCP :: {len(open_tcp)}</span>'
            '<span class="tb-i">|</span>'
            f'<span class="tb-i">UDP :: {len(open_udp)}</span>'
            '<span class="tb-i">|</span>'
            f'<span class="tb-i">SUBS :: {len(subs)}</span>'
            '<span class="tb-i">|</span>'
            f'<span class="tb-i">CVE :: {len(cve_hits)}</span>'
            '</div>\n'
        )

        # Main — AI section first, then overview
        html += '<main id="main">\n'
        ai = self.findings.get("ai", {})
        html += self._ai_section(ai)

        # Overview
        html += (
            '<section class="sec" id="overview">'
            '<div class="sec-hd"><span class="sec-ic">[*]</span><span class="sec-title">Overview</span></div>'
            '<div class="stat-grid">'
            f'<div class="sc"><div class="num">{len(open_tcp)}</div><div class="lbl">Open TCP ports</div><div class="sub">{self._esc(tcp_ports or "—")}</div></div>'
            f'<div class="sc"><div class="num">{len(open_udp)}</div><div class="lbl">Open UDP ports</div><div class="sub">{self._esc(udp_ports)}</div></div>'
            f'<div class="sc"><div class="num">{len(subs)}</div><div class="lbl">Subdomains</div><div class="sub">{self._esc(sub0)}</div></div>'
            f'<div class="sc {cve_warn}"><div class="num">{len(cve_hits)}</div><div class="lbl">CVE hints</div><div class="sub">{self._esc(cve0)}</div></div>'
            f'<div class="sc i"><div class="num">{len(set(all_techs))}</div><div class="lbl">Technologies</div><div class="sub">{self._esc(tech0)}</div></div>'
            f'<div class="sc {mhdr_warn}"><div class="num">{len(set(missing_headers))}</div><div class="lbl">Missing sec headers</div><div class="sub">{self._esc(mhdr0)}</div></div>'
            '</div></section>\n'
        )

        # DNS
        html += (
            '<section class="sec" id="dns">'
            f'<div class="sec-hd"><span class="sec-ic">[D]</span><span class="sec-title">DNS Records</span><span class="sec-ct">{len(dns)} types</span></div>'
            + self._dns_table(dns) +
            '</section>\n'
        )

        # Ports
        html += (
            '<section class="sec" id="ports">'
            f'<div class="sec-hd"><span class="sec-ic">[P]</span><span class="sec-title">Open Ports</span><span class="sec-ct">{len(open_tcp)} TCP · {len(open_udp)} UDP</span></div>'
            + self._ports_table(open_tcp, open_udp) +
            '</section>\n'
        )

        # Banners
        html += (
            '<section class="sec" id="banners">'
            f'<div class="sec-hd"><span class="sec-ic">[B]</span><span class="sec-title">Banner Grabbing</span><span class="sec-ct">{len(banners)} retrieved</span></div>'
            + self._banners_table(banners) +
            '</section>\n'
        )

        # Subdomains
        html += (
            '<section class="sec" id="subs">'
            f'<div class="sec-hd"><span class="sec-ic">[S]</span><span class="sec-title">Subdomains</span><span class="sec-ct">{len(subs)} found</span></div>'
            + self._subs_table(subs) +
            '</section>\n'
        )

        # Web
        html += (
            '<section class="sec" id="web">'
            f'<div class="sec-hd"><span class="sec-ic">[W]</span><span class="sec-title">Web Recon</span><span class="sec-ct">{len(web)} endpoints</span></div>'
            + self._web_section(web) +
            '</section>\n'
        )

        # CVE
        html += (
            '<section class="sec" id="cve">'
            f'<div class="sec-hd"><span class="sec-ic">[!]</span><span class="sec-title">CVE Alerts</span><span class="sec-ct">{len(cve_hits)} matched</span></div>'
            + self._cve_section(cve_hits) +
            '</section>\n'
        )

        # WHOIS
        html += (
            '<section class="sec" id="whois">'
            '<div class="sec-hd"><span class="sec-ic">[Q]</span><span class="sec-title">WHOIS</span></div>'
            + self._whois_section(whois_d) +
            '</section>\n'
        )

        html += (
            '</main>\n'
            '<script>\n'
            '(function(){'
            'var links=document.querySelectorAll(".nav-a");'
            'var secs=document.querySelectorAll("section.sec");'
            'function upd(){'
            'var cur="";'
            'secs.forEach(function(s){if(window.scrollY>=s.offsetTop-110)cur=s.id;});'
            'links.forEach(function(l){l.classList.toggle("active",l.getAttribute("href")==="#"+cur);});'
            '}'
            'window.addEventListener("scroll",upd,{passive:true});upd();'
            '})();'
            '\n</script>\n</body>\n</html>'
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        log("OK", f"HTML report saved -> {path}")

    # ── AI section ────────────────────────────────────────────────────────────
    def _ai_section(self, ai: dict) -> str:
        disabled = ai.get("_disabled", False) or not ai

        header = (
            '<section class="sec" id="ai">'
            '<div class="sec-hd"><span class="sec-ic">[AI]</span>'
            '<span class="sec-title">AI Analysis</span>'
            '<span class="sec-ct" style="color:var(--blu)">Claude-powered</span></div>'
        )

        if disabled:
            reason = self._esc(ai.get("_reason", "AI features not enabled"))
            body = (
                f'<div class="ai-disabled">'
                f'<div style="font-size:13px;margin-bottom:8px;color:var(--txt)">AI analysis was not run</div>'
                f'<div style="margin-bottom:8px">{reason}</div>'
                f'<div>Enable with: <code>python3 main.py -t TARGET --ai</code></div>'
                f'</div>'
            )
            return header + body + '</section>\n'

        # Risk gauge
        score     = int(ai.get("risk_score", 0))
        level     = ai.get("risk_level", "INFO").upper()
        level_cls = {"CRITICAL":"rlb-c","HIGH":"rlb-h","MEDIUM":"rlb-m","LOW":"rlb-l"}.get(level,"rlb-i")
        num_cls   = {"CRITICAL":"rc","HIGH":"rh","MEDIUM":"rm","LOW":""}.get(level,"ri")
        # SVG arc for gauge (semi-circle, score 0-100 maps to 0-180 degrees)
        import math
        pct  = max(0, min(100, score)) / 100
        ang  = pct * 180  # degrees, 0=left, 180=right
        rad  = math.radians(180 - ang)
        cx, cy, r = 50, 55, 38
        ex   = cx + r * math.cos(rad)
        ey   = cy - r * math.sin(rad)
        laf  = 1 if ang > 180 else 0
        arc_col = {"CRITICAL":"#ff4444","HIGH":"#ff8c00","MEDIUM":"#ffd700","LOW":"#00cc33"}.get(level,"#4fc3f7")

        gauge = (
            f'<div class="risk-gauge">'
            f'<svg viewBox="0 0 100 60">'
            f'<path d="M 12 55 A 38 38 0 0 1 88 55" fill="none" stroke="rgba(0,255,65,.12)" stroke-width="7" stroke-linecap="round"/>'
            f'<path d="M 12 55 A 38 38 0 {laf} 1 {ex:.1f} {ey:.1f}" fill="none" stroke="{arc_col}" stroke-width="7" stroke-linecap="round"/>'
            f'</svg>'
            f'<div class="risk-num">'
            f'<span class="rn {num_cls}">{score}</span>'
            f'<span class="rl">RISK</span>'
            f'</div></div>'
        )

        exec_sum  = self._esc(ai.get("executive_summary",""))
        atk_sum   = self._esc(ai.get("attack_surface_summary",""))

        risk_block = (
            f'<div class="risk-wrap">'
            f'{gauge}'
            f'<div class="risk-info">'
            f'<span class="risk-level-badge {level_cls}">{level}</span>'
            f'<div class="exec-sum">{exec_sum}</div>'
            + (f'<div class="atk-sum">Attack surface: {atk_sum}</div>' if atk_sum else '') +
            f'</div></div>'
        )

        # Critical findings
        findings_html = ""
        for f in ai.get("critical_findings", []):
            sev   = f.get("severity","MEDIUM").upper()
            sc    = {"CRITICAL":"bg-r","HIGH":"bg-y","MEDIUM":"bg-b","LOW":"bg-d"}.get(sev,"bg-d")
            title = self._esc(f.get("title",""))
            expl  = self._esc(f.get("explanation",""))
            rem   = self._esc(f.get("remediation",""))
            findings_html += (
                f'<div class="ai-card">'
                f'<div class="ai-card-title"><span class="bg {sc}" style="margin-right:8px;font-size:9px">{sev}</span>{title}</div>'
                f'<div class="ai-card-body">{expl}</div>'
                + (f'<div class="ai-card-fix">{rem}</div>' if rem else '') +
                f'</div>'
            )
        if not findings_html:
            findings_html = '<div class="empty">[ no critical findings ]</div>'

        # Remediation roadmap
        road_html = ""
        for item in ai.get("remediation_roadmap", []):
            pri = item.get("priority","?")
            act = self._esc(item.get("action",""))
            tf  = self._esc(item.get("timeframe",""))
            road_html += (
                f'<div class="road-row">'
                f'<div class="road-pri">{pri}</div>'
                f'<div class="road-act">{act}</div>'
                f'<span class="road-tf badge bg-d">{tf}</span>'
                f'</div>'
            )

        # Attack vectors
        vec_html = ""
        for v in ai.get("attack_vectors", []):
            vec_html += f'<div class="vec-item"><span class="vec-arrow">&rsaquo;</span><span>{self._esc(v)}</span></div>'

        # Recon suggestions
        sug_html = ""
        for s in ai.get("recon_suggestions", []):
            sug_html += f'<div class="sug-item"><span class="sug-arrow">&rsaquo;</span><span>{self._esc(s)}</span></div>'

        body = (
            risk_block +
            '<div style="margin-bottom:10px;font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em">Critical findings</div>'
            + findings_html +
            '<div class="ai-grid" style="margin-top:14px">'
            '<div>'
            '<div style="font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">Remediation roadmap</div>'
            f'<div class="tw">{road_html}</div>'
            '</div>'
            '<div>'
            '<div style="font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:8px">Attack vectors</div>'
            f'<div class="tw" style="margin-bottom:10px">{vec_html or "<div class=empty>—</div>"}</div>'
            '<div style="font-size:9px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin:10px 0 8px">Next recon steps</div>'
            f'<div class="tw">{sug_html or "<div class=empty>—</div>"}</div>'
            '</div>'
            '</div>'
        )

        return header + body + '</section>\n'

    # ── DNS ───────────────────────────────────────────────────────────────────
    def _dns_table(self, dns):
        if not dns:
            return '<div class="empty">[ no DNS data ]</div>'
        rows = ""
        type_badge = {"A":"bg-g","AAAA":"bg-g","MX":"bg-b","NS":"bg-d","TXT":"bg-d",
                      "CNAME":"bg-d","SOA":"bg-d","SRV":"bg-d","CAA":"bg-d","DNSSEC":"bg-g","PTR":"bg-y"}
        for rtype, vals in dns.items():
            if rtype == "ZONE_TRANSFER":
                zt = vals
                rows += f'<tr><td><span class="bg bg-r">AXFR</span></td><td style="color:var(--red)">Zone transfer SUCCESS on {self._esc(str(zt.get("ns","")))} — {len(zt.get("records",[]))} records exposed!</td></tr>'
                continue
            bc = type_badge.get(rtype, "bg-d")
            if isinstance(vals, list):
                for v in vals:
                    rows += f'<tr><td style="width:80px"><span class="bg {bc}">{self._esc(rtype)}</span></td><td>{self._esc(str(v))}</td></tr>'
            else:
                rows += f'<tr><td style="width:80px"><span class="bg {bc}">{self._esc(rtype)}</span></td><td>{self._esc(str(vals)[:300])}</td></tr>'
        return f'<div class="tw"><table><thead><tr><th>type</th><th>value</th></tr></thead><tbody>{rows}</tbody></table></div>'

    # ── Ports ─────────────────────────────────────────────────────────────────
    def _ports_table(self, tcp, udp):
        if not tcp and not udp:
            return '<div class="empty">[ no open ports ]</div>'
        rows = ""
        risky_ports = {21,23,3389,5900,1433,27017,6379,9200,2049,111,137,138}
        for port, info in sorted(tcp.items()):
            svc    = self._esc(info.get("service","unknown"))
            banner = self._esc(info.get("banner","")[:80])
            bw     = min(100, max(4, port // 655))
            risky  = port in risky_ports
            sb     = '<span class="bg bg-r">RISKY</span>' if risky else '<span class="bg bg-g">OPEN</span>'
            rows  += (f'<tr><td><b style="color:var(--g)">{port}</b></td><td>TCP</td>'
                      f'<td><span class="bg bg-d">{svc}</span></td><td>{sb}</td>'
                      f'<td><div class="pb"><div class="pf" style="width:{bw}px"></div></div></td>'
                      f'<td style="font-size:11px;color:var(--dim);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{banner}</td></tr>')
        for port, info in sorted(udp.items()):
            svc  = self._esc(info.get("service","unknown"))
            rows += (f'<tr><td><b style="color:var(--blu)">{port}</b></td><td style="color:var(--blu)">UDP</td>'
                     f'<td><span class="bg bg-b">{svc}</span></td><td><span class="bg bg-b">OPEN</span></td>'
                     f'<td></td><td style="font-size:11px;color:var(--dim)">{self._esc(str(info.get("response",""))[:80])}</td></tr>')
        return (f'<div class="tw"><table><thead><tr><th>port</th><th>proto</th>'
                f'<th>service</th><th>status</th><th>relative</th><th>banner</th></tr></thead>'
                f'<tbody>{rows}</tbody></table></div>')

    # ── Banners ───────────────────────────────────────────────────────────────
    def _banners_table(self, banners):
        if not banners:
            return '<div class="empty">[ no banners retrieved ]</div>'
        rows = ""
        for port, data in sorted(banners.items()):
            banner  = self._esc(data.get("banner","")[:160])
            cves    = data.get("cves",[])
            cv_html = " ".join(f'<span class="bg bg-r">{self._esc(c["id"])}</span>' for c in cves)
            rows   += (f'<tr><td style="width:60px"><b>{port}</b></td>'
                       f'<td style="font-size:11px">{banner}</td>'
                       f'<td>{cv_html or "<span style=color:var(--dim)>—</span>"}</td></tr>')
        return f'<div class="tw"><table><thead><tr><th>port</th><th>banner</th><th>cve hints</th></tr></thead><tbody>{rows}</tbody></table></div>'

    # ── Subdomains ────────────────────────────────────────────────────────────
    def _subs_table(self, subs):
        if not subs:
            return '<div class="empty">[ no subdomains found ]</div>'
        rows = ""
        for s in subs:
            fqdn = self._esc(s.get("subdomain",""))
            ips  = self._esc(", ".join(s.get("ips",[])) or "—")
            src  = s.get("source","")
            sb   = (f'<span class="src-c">crt.sh</span>' if "crt" in src else
                    f'<span class="src-w">wayback</span>' if "wayback" in src else
                    f'<span class="src-b">bruteforce</span>')
            rows += f'<tr><td style="color:var(--g)">{fqdn}</td><td style="color:var(--dim)">{ips}</td><td>{sb}</td></tr>'
        return f'<div class="tw"><table><thead><tr><th>subdomain</th><th>ip address(es)</th><th>source</th></tr></thead><tbody>{rows}</tbody></table></div>'

    # ── Web ───────────────────────────────────────────────────────────────────
    def _web_section(self, web):
        if not web:
            return '<div class="empty">[ no web data ]</div>'
        out = ""
        for url, data in web.items():
            status  = data.get("status_code","")
            title   = self._esc(data.get("title","")[:90])
            techs   = data.get("technologies",[])
            missing = data.get("missing_security_headers",[])
            present = data.get("present_security_headers",{})
            cookies = data.get("cookies",{})
            ssl     = data.get("ssl") or {}
            robots  = data.get("robots_txt")
            sitemap = data.get("sitemap")
            sc      = "var(--g)" if str(status).startswith("2") else "var(--ylw)" if str(status).startswith("3") else "var(--red)"
            tech_h  = "".join(f'<span class="tag">{self._esc(t)}</span>' for t in techs) or '<span style="color:var(--dim);font-size:11px">none detected</span>'
            miss_h  = "".join(f'<span class="wt">{self._esc(h)}</span>' for h in missing)
            pres_h  = "".join(f'<span class="ot">{self._esc(h)}</span>' for h in present)
            ck_rows = ""
            for name, cd in cookies.items():
                flags   = cd.get("flags",[])
                fl_html = "".join(f'<span class="bg bg-r" style="font-size:9px;margin-left:3px">{self._esc(f)}</span>' for f in flags)
                sb_ck   = '<span class="bg bg-g" style="font-size:9px">secure</span>' if cd.get("secure") else '<span class="bg bg-r" style="font-size:9px">no-Secure</span>'
                ck_rows += f'<div style="padding:3px 0;border-bottom:1px solid rgba(0,255,65,.04);font-size:11px;color:var(--txt)">{self._esc(name)} {sb_ck}{fl_html}</div>'
            ssl_html = ""
            if ssl and not ssl.get("error"):
                days      = ssl.get("days_until_expiry","?")
                days_col  = "var(--red)" if isinstance(days,int) and days < 30 else "var(--g)"
                ssl_html  = (f'<div class="ep-sec"><div class="ep-lbl">SSL / TLS</div>'
                             f'<div class="kv">'
                             f'<div class="kv-r"><div class="kk">version</div><div class="kv">{self._esc(ssl.get("tls_version","—"))}</div></div>'
                             f'<div class="kv-r"><div class="kk">cipher</div><div class="kv">{self._esc(ssl.get("cipher","—"))}</div></div>'
                             f'<div class="kv-r"><div class="kk">expires&nbsp;in</div><div class="kv" style="color:{days_col}">{days} days</div></div>'
                             f'<div class="kv-r"><div class="kk">issuer</div><div class="kv">{self._esc(ssl.get("issuer","—"))}</div></div>'
                             f'<div class="kv-r"><div class="kk">SANs</div><div class="kv">{self._esc(", ".join(ssl.get("san",[])[:6]))}</div></div>'
                             f'</div></div>')
            rb_html = ""
            if robots:
                dl = [l for l in robots.splitlines() if l.lower().startswith("disallow")][:8]
                dl_html = "".join(f'<div style="font-size:11px;color:var(--dim);padding:1px 0">{self._esc(l)}</div>' for l in dl)
                rb_html = f'<div class="ep-sec"><div class="ep-lbl">robots.txt — {len(dl)} disallow entries</div>{dl_html}</div>'
            sm_badge = '<span class="bg bg-g" style="font-size:9px;margin-left:4px">sitemap.xml</span>' if sitemap else ''
            rb_badge = '<span class="bg bg-d" style="font-size:9px;margin-left:4px">robots.txt</span>' if robots else ''
            out += (f'<div class="ep">'
                    f'<div class="ep-hd"><span class="ep-url">{self._esc(url)}</span>'
                    f'<span class="ep-sts" style="color:{sc}">HTTP {status}</span>'
                    f'<span class="ep-ttl">{title}</span>{sm_badge}{rb_badge}</div>'
                    f'<div class="ep-sec"><div class="ep-lbl">technologies</div><div class="tag-wrap">{tech_h}</div></div>'
                    f'<div class="ep-sec"><div class="ep-lbl">security headers</div><div>{miss_h}{pres_h}</div></div>'
                    + (f'<div class="ep-sec"><div class="ep-lbl">cookies</div>{ck_rows}</div>' if ck_rows else '')
                    + ssl_html + rb_html +
                    f'</div>')
        return out

    # ── CVE ───────────────────────────────────────────────────────────────────
    def _cve_section(self, cve_hits):
        if not cve_hits:
            return '<div class="empty" style="color:var(--gd)">[ no CVE hints matched ]</div>'
        rows = "".join(
            f'<div class="cr"><span class="id">{self._esc(cid)}</span><span class="pt">port {port}</span><span class="ds">{self._esc(desc)}</span></div>'
            for port, cid, desc in cve_hits
        )
        return f'<div class="tw danger">{rows}</div>'

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    def _whois_section(self, whois_d):
        if not whois_d:
            return '<div class="empty">[ no WHOIS data ]</div>'
        order = ["registrar","org","country","creation_date","expiration_date",
                 "updated_date","name_servers","emails","dnssec","status"]
        rows  = ""
        done  = set()
        for key in order:
            val = whois_d.get(key)
            if val:
                rows += f'<div class="kv-r"><div class="kk">{self._esc(key)}</div><div class="kv">{self._esc(str(val)[:200])}</div></div>'
                done.add(key)
        for key, val in whois_d.items():
            if key not in done and key != "raw" and val:
                rows += f'<div class="kv-r"><div class="kk">{self._esc(key)}</div><div class="kv">{self._esc(str(val)[:200])}</div></div>'
        return f'<div class="tw"><div class="kv">{rows}</div></div>'

    # ── helper ────────────────────────────────────────────────────────────────
    @staticmethod
    def _esc(s):
        return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

    # ── terminal summary ──────────────────────────────────────────────────────
    def print_summary(self):
        section("Engagement Summary")
        try:
            from rich.console import Console
            from rich.table import Table
            from rich import box
            console = Console()
            t = Table(title=f"Summary — {self.target}", box=box.ROUNDED,
                      border_style="green", header_style="bold green", show_lines=True)
            t.add_column("Module", style="bold white", width=20)
            t.add_column("Result", width=55)
            dns      = self.findings.get("dns", {})
            ports    = self.findings.get("ports", {})
            open_tcp = ports.get("open_tcp", {})
            open_udp = ports.get("open_udp", {})
            subs     = self.findings.get("subdomains", [])
            web      = self.findings.get("web", {})
            banners  = self.findings.get("banners", {})
            whois_d  = self.findings.get("whois", {})
            techs    = list({x for d in web.values() for x in d.get("technologies", [])})
            cves     = [c["id"] for b in banners.values() for c in b.get("cves", [])]
            t.add_row("DNS Records",   ", ".join(dns.keys()) or "None")
            t.add_row("Open TCP",      ", ".join(f"{p}({v['service']})" for p, v in sorted(open_tcp.items()))[:60] or "None")
            t.add_row("Open UDP",      ", ".join(f"{p}({v['service']})" for p, v in sorted(open_udp.items()))[:60] or "None")
            t.add_row("Subdomains",    f"{len(subs)} found" + (f": {', '.join(s['subdomain'] for s in subs[:3])}" if subs else ""))
            t.add_row("Technologies",  ", ".join(techs[:8]) or "None")
            t.add_row("CVE Hints",     ", ".join(cves) or "None")
            t.add_row("WHOIS",         str(whois_d.get("registrar", "N/A"))[:55])
            console.print(t)
        except ImportError:
            for module, data in self.findings.items():
                print(f"  {module}: {str(data)[:80]}")
