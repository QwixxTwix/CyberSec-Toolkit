"""
Bug Bounty Autopilot — расширенный.
Author: idqwixxa

⚠ Только для авторизованных bug bounty программ.

Единый pipeline:
    1. Subdomain discovery
    2. Live host detection
    3. Tech fingerprint
    4. Port scan
    5. Takeover check
    6. Directory brute (sensitive paths)
    7. Wayback URLs
    8. JS secrets scan
    9. JS endpoint extraction (fetch/axios regex)
    10. CORS misconfig check
    11. GraphQL detection
    12. Findings → notes
    13. Auto-report (HTML/JSON/MD)
    14. Notify

Профили: quick / full / deep.
Интеграция с bugbounty_autoscan, subdomain_takeover_v2,
js_secrets, osint_pro, report_pack, notes, notifier.
"""
import asyncio
import json
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host

console = Console()
log = get_logger(__name__)

AP_DIR = REPORT_DIR / "autopilot"
AP_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Profiles
# ===========================================================================

PROFILES = {
    "quick": {
        "max_subs": 500,
        "port_range": "top100",
        "dir_brute": False,
        "wayback": False,
        "js_secrets": False,
        "js_endpoints": False,
        "cors": False,
        "graphql": False,
        "takeover": True,
        "timeout_min": 5,
    },
    "full": {
        "max_subs": 5000,
        "port_range": "top1000",
        "dir_brute": True,
        "wayback": True,
        "js_secrets": True,
        "js_endpoints": True,
        "cors": True,
        "graphql": True,
        "takeover": True,
        "timeout_min": 30,
    },
    "deep": {
        "max_subs": 20000,
        "port_range": "top1000",
        "dir_brute": True,
        "wayback": True,
        "js_secrets": True,
        "js_endpoints": True,
        "cors": True,
        "graphql": True,
        "takeover": True,
        "timeout_min": 180,
    },
}


# ===========================================================================
# Model
# ===========================================================================

@dataclass
class AutopilotRun:
    domain: str
    profile: str
    started: str
    finished: str = ""
    duration_sec: float = 0.0
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict] = field(default_factory=list)
    tech: dict = field(default_factory=dict)
    open_ports: dict = field(default_factory=dict)
    takeovers: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    wayback_urls: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    cors_findings: list[dict] = field(default_factory=list)
    graphql_endpoints: list[str] = field(default_factory=list)
    findings_ids: list[int] = field(default_factory=list)
    report_path: str = ""
    errors: list[str] = field(default_factory=list)

    def summary_dict(self) -> dict:
        return {
            "domain": self.domain,
            "profile": self.profile,
            "subdomains": len(self.subdomains),
            "live_hosts": len(self.live_hosts),
            "open_ports": sum(len(v) for v in self.open_ports.values()),
            "takeovers": len(self.takeovers),
            "sensitive_paths": len(self.sensitive_paths),
            "wayback": len(self.wayback_urls),
            "secrets": len(self.secrets),
            "js_endpoints": len(self.js_endpoints),
            "cors_findings": len(self.cors_findings),
            "graphql": len(self.graphql_endpoints),
            "findings": len(self.findings_ids),
            "duration": self.duration_sec,
        }


# ===========================================================================
# Stage runners
# ===========================================================================

def _run_subdomain_stage(domain: str, profile: dict,
                          run: AutopilotRun) -> None:
    console.print("\n[bold cyan]▶ Stage 1/13: Subdomain discovery"
                  "[/bold cyan]")
    try:
        from modules import bugbounty_autoscan as bba
        cfg = {
            "max_subs": profile["max_subs"],
            "wordlist": "subdomains-top1million-5000.txt",
            "threads_subs": 60,
            "timeout": 10,
        }
        subs, wildcard = bba.discover_subdomains(domain, cfg)
        run.subdomains = [s.name for s in subs]
        console.print(f"[green]✓ Найдено {len(run.subdomains)} поддоменов"
                      f"[/green]")
    except Exception as exc:
        console.print(f"[red]Stage 1: {exc}[/red]")
        run.errors.append(f"subs: {exc}")


def _run_live_hosts_stage(domain: str, run: AutopilotRun) -> None:
    console.print("\n[bold cyan]▶ Stage 2/13: Live hosts[/bold cyan]")
    import socket
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _check(sub: str) -> dict | None:
        try:
            ip = socket.gethostbyname(sub)
            return {"subdomain": sub, "ip": ip, "scheme": "https"}
        except Exception:
            return None

    live: list[dict] = []
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = [ex.submit(_check, s) for s in run.subdomains[:1000]]
        for f in as_completed(futs):
            r = f.result()
            if r:
                live.append(r)
    run.live_hosts = live[:300]
    console.print(f"[green]✓ Live hosts: {len(run.live_hosts)}[/green]")


def _run_tech_stage(run: AutopilotRun) -> None:
    console.print("\n[bold cyan]▶ Stage 3/13: Tech fingerprint"
                  "[/bold cyan]")
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _one(h: dict) -> tuple[str, list[str]]:
        url = f"{h['scheme']}://{h['subdomain']}"
        markers: list[str] = []
        try:
            r = requests.get(url, timeout=10, verify=False,
                              headers={"User-Agent": config.USER_AGENT},
                              allow_redirects=True)
            if r.headers.get("Server"):
                markers.append(f"Server:{r.headers['Server']}")
            for c in ("X-Powered-By", "X-Generator", "X-AspNet-Version"):
                if r.headers.get(c):
                    markers.append(f"{c}:{r.headers[c]}")
            body = r.text.lower()
            for name, mark in [
                ("WordPress", "wp-content"),
                ("React", "data-reactroot"),
                ("Next.js", "__NEXT_DATA__"),
                ("Vue", "data-v-"),
                ("Angular", "ng-version"),
                ("Cloudflare", "cf-ray"),
                ("Nginx", "nginx"),
                ("Apache", "apache"),
                ("jQuery", "jquery"),
                ("Bootstrap", "bootstrap"),
                ("GraphQL", "graphql"),
            ]:
                if mark in body or mark in str(r.headers).lower():
                    markers.append(name)
        except Exception:
            pass
        return url, markers

    tech: dict = {}
    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(_one, h) for h in run.live_hosts[:80]]
        for f in as_completed(futs):
            try:
                url, m = f.result()
                if m:
                    tech[url] = m
            except Exception:
                pass
    run.tech = tech
    console.print(f"[green]✓ Проверено {len(tech)} хостов[/green]")


def _run_ports_stage(run: AutopilotRun, profile: dict) -> None:
    console.print("\n[bold cyan]▶ Stage 4/13: Port scan[/bold cyan]")
    try:
        import socket
        from concurrent.futures import ThreadPoolExecutor, as_completed

        top_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            161, 389, 443, 445, 993, 995, 1433, 3306, 3389,
            5432, 5900, 6379, 8080, 8443, 9200, 27017,
            8000, 8008, 8888, 9090, 5000, 7001, 6443, 10250,
        ]
        ips = sorted({h["ip"] for h in run.live_hosts})
        console.print(f"[dim]Сканирую {len(ips)} IP × {len(top_ports)} "
                      f"портов…[/dim]")

        def _check(ip_port):
            ip, port = ip_port
            try:
                with socket.create_connection((ip, port), timeout=1.5):
                    return (ip, port)
            except Exception:
                return None

        open_ports: dict[str, list[int]] = {}
        with ThreadPoolExecutor(max_workers=100) as ex:
            futs = [ex.submit(_check, (ip, p))
                    for ip in ips[:100] for p in top_ports]
            for f in as_completed(futs):
                r = f.result()
                if r:
                    ip, port = r
                    open_ports.setdefault(ip, []).append(port)
        run.open_ports = open_ports
        console.print(f"[green]✓ IP с открытыми портами: "
                      f"{len(open_ports)}[/green]")
    except Exception as exc:
        console.print(f"[red]Stage 4: {exc}[/red]")
        run.errors.append(f"ports: {exc}")


def _run_takeover_stage(domain: str, run: AutopilotRun,
                         profile: dict) -> None:
    if not profile.get("takeover"):
        return
    console.print("\n[bold cyan]▶ Stage 5/13: Takeover check[/bold cyan]")
    try:
        from modules import subdomain_takeover_v2 as t2
        candidates = list(set(
            [h["subdomain"] for h in run.live_hosts]
            + run.subdomains[:200]))
        findings = t2.scan_list(",".join(candidates[:300]),
                                 threads=20, timeout=8)
        run.takeovers = [f.subdomain for f in findings if f.dangling]
        console.print(f"[green]✓ Takeover-кандидатов: "
                      f"{len(run.takeovers)}[/green]")
    except Exception as exc:
        console.print(f"[red]Stage 5: {exc}[/red]")
        run.errors.append(f"takeover: {exc}")


SENSITIVE_PATHS_AP = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.bak",
    "/admin", "/admin/", "/administrator/", "/wp-admin",
    "/backup", "/backup.zip", "/backup.sql", "/db.sql",
    "/api", "/api/v1", "/api/v2", "/swagger.json", "/openapi.json",
    "/swagger-ui.html", "/graphql", "/api/graphql",
    "/actuator/health", "/actuator/env", "/actuator",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/server-status", "/server-info", "/phpinfo.php",
    "/.DS_Store", "/.htaccess", "/config.json",
    "/health", "/healthz", "/status", "/metrics",
    "/console/", "/.idea/", "/.vscode/",
]


def _run_dir_brute_stage(run: AutopilotRun, profile: dict) -> None:
    if not profile.get("dir_brute"):
        console.print("\n[dim]Stage 6/13: dir brute — пропущено[/dim]")
        return
    console.print("\n[bold cyan]▶ Stage 6/13: Directory brute"
                  "[/bold cyan]")
    from concurrent.futures import ThreadPoolExecutor, as_completed

    sensitive: list[str] = []

    def _check_one(args):
        host, scheme = args
        url_base = f"{scheme}://{host}"
        found: list[str] = []
        for p in SENSITIVE_PATHS_AP:
            try:
                r = requests.head(url_base + p, timeout=5, verify=False,
                                   allow_redirects=False,
                                   headers={"User-Agent": config.USER_AGENT})
                if r.status_code in (200, 401, 403, 405):
                    found.append(f"{url_base}{p} [{r.status_code}]")
            except Exception:
                continue
        return found

    with ThreadPoolExecutor(max_workers=20) as ex:
        futs = [ex.submit(_check_one, (h["subdomain"], h["scheme"]))
                for h in run.live_hosts[:40]]
        for f in as_completed(futs):
            try:
                sensitive.extend(f.result())
            except Exception:
                pass

    run.sensitive_paths = sensitive
    console.print(f"[green]✓ Sensitive paths: {len(sensitive)}[/green]")


def _run_wayback_stage(domain: str, run: AutopilotRun,
                        profile: dict) -> None:
    if not profile.get("wayback"):
        console.print("\n[dim]Stage 7/13: wayback — пропущено[/dim]")
        return
    console.print("\n[bold cyan]▶ Stage 7/13: Wayback[/bold cyan]")
    try:
        from modules import osint_pro
        urls = osint_pro.wayback_lookup(domain, limit=100)
        run.wayback_urls = [u["url"] for u in urls][:200]
        console.print(f"[green]✓ Wayback URLs: {len(run.wayback_urls)}"
                      f"[/green]")
    except Exception as exc:
        console.print(f"[red]Stage 7: {exc}[/red]")
        run.errors.append(f"wayback: {exc}")


def _run_js_secrets_stage(run: AutopilotRun, profile: dict) -> None:
    if not profile.get("js_secrets"):
        console.print("\n[dim]Stage 8/13: JS secrets — пропущено[/dim]")
        return
    console.print("\n[bold cyan]▶ Stage 8/13: JS secrets[/bold cyan]")
    try:
        from modules import js_secrets
        all_secrets: list[dict] = []
        for h in run.live_hosts[:15]:
            url = f"{h['scheme']}://{h['subdomain']}"
            try:
                secrets = js_secrets.scan_url(url, max_files=20,
                                               validate=False)
                for s in secrets:
                    all_secrets.append({
                        "kind": s.kind,
                        "severity": s.severity,
                        "source": s.source_url,
                        "value_masked": s.value[:16] + "...",
                    })
            except Exception:
                continue
        run.secrets = all_secrets
        console.print(f"[green]✓ Секретов найдено: "
                      f"{len(all_secrets)}[/green]")
    except Exception as exc:
        console.print(f"[red]Stage 8: {exc}[/red]")
        run.errors.append(f"secrets: {exc}")


# ===========================================================================
# Stage 9: JS endpoints
# ===========================================================================

_JS_EP_REGEXES = [
    re.compile(r"""["'](/api/[a-zA-Z0-9_\-/]+)["']"""),
    re.compile(r"""["'](/v\d+/[a-zA-Z0-9_\-/]+)["']"""),
    re.compile(r"""fetch\(\s*["']([^"']+)["']"""),
    re.compile(r"""axios\.[a-z]+\(\s*["']([^"']+)["']"""),
    re.compile(r"""\.open\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']"""),
]


def _run_js_endpoints_stage(run: AutopilotRun, profile: dict) -> None:
    if not profile.get("js_endpoints"):
        console.print("\n[dim]Stage 9/13: JS endpoints — пропущено[/dim]")
        return
    console.print("\n[bold cyan]▶ Stage 9/13: JS endpoints[/bold cyan]")

    endpoints: set[str] = set()
    for h in run.live_hosts[:15]:
        url = f"{h['scheme']}://{h['subdomain']}"
        try:
            r = requests.get(url, timeout=10, verify=False,
                              headers={"User-Agent": config.USER_AGENT})
            for regex in _JS_EP_REGEXES:
                for m in regex.finditer(r.text):
                    endpoints.add(m.group(1))
        except Exception:
            continue

    run.js_endpoints = sorted(endpoints)[:300]
    console.print(f"[green]✓ JS endpoints: {len(run.js_endpoints)}"
                  f"[/green]")


# ===========================================================================
# Stage 10: CORS misconfig
# ===========================================================================

def _run_cors_stage(run: AutopilotRun, profile: dict) -> None:
    if not profile.get("cors"):
        console.print("\n[dim]Stage 10/13: CORS — пропущено[/dim]")
        return
    console.print("\n[bold cyan]▶ Stage 10/13: CORS check[/bold cyan]")

    origins = [
        "https://evil-attacker.com",
        "null",
        "https://sub.evil-attacker.com",
    ]
    findings: list[dict] = []
    for h in run.live_hosts[:30]:
        url = f"{h['scheme']}://{h['subdomain']}"
        for origin in origins:
            try:
                r = requests.options(url, timeout=8, verify=False,
                                       headers={
                                           "User-Agent": config.USER_AGENT,
                                           "Origin": origin,
                                           "Access-Control-Request-Method":
                                               "GET",
                                       })
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                if acao == origin or acao == "*":
                    sev = "high" if acac.lower() == "true" else "medium"
                    findings.append({
                        "url": url,
                        "origin_sent": origin,
                        "acao": acao,
                        "acac": acac,
                        "severity": sev,
                    })
                    break
            except Exception:
                continue
    run.cors_findings = findings
    if findings:
        console.print(f"[red]⚠ CORS: {len(findings)}[/red]")
    else:
        console.print("[green]✓ CORS misconfig не найдена[/green]")


# ===========================================================================
# Stage 11: GraphQL detection
# ===========================================================================

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/gql",
    "/v1/graphql", "/v2/graphql", "/query", "/gql",
    "/altair", "/playground", "/api/v1/graphql",
]


def _run_graphql_stage(run: AutopilotRun, profile: dict) -> None:
    if not profile.get("graphql"):
        console.print("\n[dim]Stage 11/13: GraphQL — пропущено[/dim]")
        return
    console.print("\n[bold cyan]▶ Stage 11/13: GraphQL detection"
                  "[/bold cyan]")

    found: list[str] = []
    for h in run.live_hosts[:30]:
        base = f"{h['scheme']}://{h['subdomain']}"
        for path in GRAPHQL_PATHS:
            try:
                r = requests.post(base + path, json={"query": "{__typename}"},
                                   timeout=6, verify=False,
                                   headers={"User-Agent": config.USER_AGENT,
                                            "Content-Type": "application/json"})
                if r.status_code in (200, 400):
                    try:
                        data = r.json()
                        if "data" in data or "errors" in data:
                            found.append(base + path)
                            break
                    except Exception:
                        pass
            except Exception:
                continue
    run.graphql_endpoints = found
    if found:
        console.print(f"[yellow]⚠ GraphQL endpoints: {len(found)}[/yellow]")
    else:
        console.print("[green]✓ GraphQL не найден[/green]")


# ===========================================================================
# Stage 12: Findings → notes
# ===========================================================================

def _run_findings_stage(run: AutopilotRun, domain: str) -> None:
    console.print("\n[bold cyan]▶ Stage 12/13: Findings → notes"
                  "[/bold cyan]")

    try:
        from modules import notes
    except Exception as exc:
        console.print(f"[red]notes: {exc}[/red]")
        return

    finding_ids: list[int] = []

    # Takeover
    for sub in run.takeovers:
        try:
            nid = notes.add_note(
                kind="finding",
                title=f"Subdomain Takeover: {sub}",
                target=sub,
                severity="high",
                status="open",
                tags=["takeover", "autopilot"],
                body=f"Dangling CNAME. Проверь вручную.",
            )
            if nid > 0:
                finding_ids.append(nid)
        except Exception:
            pass

    # Sensitive paths
    for path in run.sensitive_paths:
        try:
            nid = notes.add_note(
                kind="finding",
                title=f"Sensitive path: {path.split(' [')[0]}",
                target=domain,
                severity="medium",
                status="open",
                tags=["exposure", "autopilot"],
                body=f"Найден доступный путь: {path}",
            )
            if nid > 0:
                finding_ids.append(nid)
        except Exception:
            pass

    # Secrets
    for s in run.secrets:
        sev = "critical" if s["severity"] == "critical" else "high"
        try:
            nid = notes.add_note(
                kind="finding",
                title=f"Secret in JS: {s['kind']}",
                target=domain,
                severity=sev,
                status="open",
                tags=["secrets", "js", "autopilot"],
                body=(f"Type: {s['kind']}\n"
                      f"Source: {s['source']}\n"
                      f"Value (masked): {s['value_masked']}"),
            )
            if nid > 0:
                finding_ids.append(nid)
        except Exception:
            pass

    # CORS
    for c in run.cors_findings:
        try:
            nid = notes.add_note(
                kind="finding",
                title=f"CORS misconfig on {c['url']}",
                target=domain,
                severity=c["severity"],
                status="open",
                tags=["cors", "autopilot"],
                body=(f"URL: {c['url']}\n"
                      f"Origin sent: {c['origin_sent']}\n"
                      f"ACAO: {c['acao']}\n"
                      f"ACAC: {c['acac']}"),
            )
            if nid > 0:
                finding_ids.append(nid)
        except Exception:
            pass

    # GraphQL
    for ep in run.graphql_endpoints:
        try:
            nid = notes.add_note(
                kind="finding",
                title=f"GraphQL endpoint: {ep}",
                target=domain,
                severity="low",
                status="open",
                tags=["graphql", "autopilot"],
                body=f"Проверь introspection: POST {ep} с "
                     f'{{"query":"{{__schema{{types{{name}}}}}}"}}',
            )
            if nid > 0:
                finding_ids.append(nid)
        except Exception:
            pass

    run.findings_ids = finding_ids
    console.print(f"[green]✓ Findings создано: {len(finding_ids)}"
                  f"[/green]")


# ===========================================================================
# Stage 13: Report
# ===========================================================================

def _run_report_stage(run: AutopilotRun) -> None:
    console.print("\n[bold cyan]▶ Stage 13/13: Report[/bold cyan]")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = run.domain.replace(".", "_")
    base = AP_DIR / f"autopilot_{safe}_{ts}"

    # JSON
    try:
        base.with_suffix(".json").write_text(
            json.dumps(asdict(run), indent=2, ensure_ascii=False,
                        default=str),
            encoding="utf-8")
        run.report_path = str(base.with_suffix(".json"))
        console.print(f"[green]✓ JSON: {run.report_path}[/green]")
    except Exception as exc:
        console.print(f"[red]JSON: {exc}[/red]")

    # HTML (использует bugbounty_autoscan style)
    try:
        html = _make_autopilot_html(run)
        base.with_suffix(".html").write_text(html, encoding="utf-8")
        console.print(f"[green]✓ HTML: {base.with_suffix('.html')}"
                      f"[/green]")
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")


HTML_CSS_AP = """
body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;
     padding:24px;line-height:1.5;}
h1{color:#00ff9c;border-bottom:2px solid #00ff9c;padding-bottom:8px;}
h2{color:#00ff9c;margin-top:32px;border-left:4px solid #00ff9c;
   padding-left:12px;}
.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
         gap:12px;margin:20px 0;}
.card{background:#0d0d0d;border:1px solid #222;padding:14px;
      border-radius:4px;}
.card .num{font-size:26px;color:#00ff9c;font-weight:bold;}
.card .label{font-size:12px;color:#888;margin-top:4px;}
table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px;}
th{background:#111;color:#00ff9c;padding:8px;text-align:left;
   border:1px solid #222;}
td{padding:6px 8px;border:1px solid #222;word-break:break-all;}
tr:nth-child(even){background:#0d0d0d;}
.warn{color:#ff7a40;}
.crit{color:#ff4040;font-weight:bold;}
.ok{color:#00ff9c;}
.muted{color:#666;}
.footer{margin-top:40px;padding-top:16px;border-top:1px solid #222;
        color:#555;font-size:12px;text-align:center;}
"""


def _esc(v: Any) -> str:
    import html
    return html.escape(str(v if v is not None else ""))


def _make_autopilot_html(run: AutopilotRun) -> str:
    s = run.summary_dict()
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>Autopilot — {_esc(run.domain)}</title>",
        f"<style>{HTML_CSS_AP}</style></head><body>",
        f"<h1>🎯 Autopilot — {_esc(run.domain)}</h1>",
        f"<p>Profile: <b>{_esc(run.profile)}</b> | "
        f"Duration: {run.duration_sec:.1f}s | "
        f"Started: {_esc(run.started)}</p>",
        "<div class='summary'>",
    ]
    for label, val in [
        ("Subdomains", s["subdomains"]),
        ("Live hosts", s["live_hosts"]),
        ("Open ports", s["open_ports"]),
        ("Takeovers", s["takeovers"]),
        ("Sensitive paths", s["sensitive_paths"]),
        ("Wayback", s["wayback"]),
        ("Secrets", s["secrets"]),
        ("JS endpoints", s["js_endpoints"]),
        ("CORS", s["cors_findings"]),
        ("GraphQL", s["graphql"]),
        ("Findings", s["findings"]),
    ]:
        parts.append(f"<div class='card'><div class='num'>{val}</div>"
                     f"<div class='label'>{_esc(label)}</div></div>")
    parts.append("</div>")

    if run.takeovers:
        parts.append(f"<h2>🎯 Takeover ({len(run.takeovers)})</h2><ul>")
        for x in run.takeovers:
            parts.append(f"<li class='crit'>{_esc(x)}</li>")
        parts.append("</ul>")

    if run.sensitive_paths:
        parts.append(f"<h2>⚠ Sensitive paths "
                     f"({len(run.sensitive_paths)})</h2><ul>")
        for x in run.sensitive_paths[:100]:
            parts.append(f"<li class='warn'>{_esc(x)}</li>")
        parts.append("</ul>")

    if run.secrets:
        parts.append(f"<h2>🔐 Secrets ({len(run.secrets)})</h2><table>"
                     "<tr><th>Kind</th><th>Severity</th><th>Source</th></tr>")
        for x in run.secrets:
            parts.append(f"<tr><td>{_esc(x['kind'])}</td>"
                         f"<td>{_esc(x['severity'])}</td>"
                         f"<td>{_esc(x['source'][:80])}</td></tr>")
        parts.append("</table>")

    if run.cors_findings:
        parts.append(f"<h2>🌐 CORS ({len(run.cors_findings)})</h2><table>"
                     "<tr><th>URL</th><th>Origin</th><th>ACAO</th>"
                     "<th>ACAC</th><th>Sev</th></tr>")
        for x in run.cors_findings:
            parts.append(f"<tr><td>{_esc(x['url'])}</td>"
                         f"<td>{_esc(x['origin_sent'])}</td>"
                         f"<td>{_esc(x['acao'])}</td>"
                         f"<td>{_esc(x['acac'])}</td>"
                         f"<td>{_esc(x['severity'])}</td></tr>")
        parts.append("</table>")

    if run.graphql_endpoints:
        parts.append(f"<h2>GraphQL ({len(run.graphql_endpoints)})</h2><ul>")
        for x in run.graphql_endpoints:
            parts.append(f"<li>{_esc(x)}</li>")
        parts.append("</ul>")

    if run.js_endpoints:
        parts.append(f"<h2>📜 JS endpoints "
                     f"({len(run.js_endpoints)})</h2><ul>")
        for x in run.js_endpoints[:100]:
            parts.append(f"<li class='muted'>{_esc(x)}</li>")
        parts.append("</ul>")

    if run.errors:
        parts.append(f"<h2>Errors ({len(run.errors)})</h2><ul>")
        for e in run.errors:
            parts.append(f"<li class='muted'>{_esc(e)}</li>")
        parts.append("</ul>")

    parts.append(f"<div class='footer'>Bug Bounty Autopilot — "
                 f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>")
    parts.append("</body></html>")
    return "\n".join(parts)


# ===========================================================================
# Notify
# ===========================================================================

def _notify(run: AutopilotRun) -> None:
    try:
        from modules import notifier
    except Exception:
        return
    s = run.summary_dict()
    msg = (
        f"Profile: {run.profile}\n"
        f"Duration: {s['duration']:.1f}s\n\n"
        f"• Subdomains: {s['subdomains']}\n"
        f"• Live hosts: {s['live_hosts']}\n"
        f"• Open ports: {s['open_ports']}\n"
        f"• Takeovers: {s['takeovers']}\n"
        f"• Sensitive: {s['sensitive_paths']}\n"
        f"• Wayback: {s['wayback']}\n"
        f"• Secrets: {s['secrets']}\n"
        f"• JS endpoints: {s['js_endpoints']}\n"
        f"• CORS: {s['cors_findings']}\n"
        f"• GraphQL: {s['graphql']}\n"
        f"• Findings: {s['findings']}\n"
    )
    if run.errors:
        msg += f"\n⚠ Errors: {len(run.errors)}"
    try:
        notifier.notify_all(f"🎯 Autopilot: {run.domain}", msg)
    except Exception:
        pass


# ===========================================================================
# Orchestrator
# ===========================================================================

def run_pipeline(domain: str, profile: str = "full",
                  skip_stages: list[str] | None = None) -> AutopilotRun:
    if not confirm_external(domain):
        return AutopilotRun(domain=domain, profile=profile, started="")

    domain = extract_host(domain).lower()
    prof = PROFILES.get(profile, PROFILES["full"])

    console.print(f"\n[bold cyan]🚀 Bug Bounty Autopilot[/bold cyan]")
    console.print(f"[cyan]Domain:[/cyan] {domain}")
    console.print(f"[cyan]Profile:[/cyan] {profile} "
                  f"(~{prof['timeout_min']} min)")
    console.print(f"[dim]Stages: subs → live → tech → ports → takeover "
                  f"→ dir → wayback → secrets → js-ep → cors → graphql "
                  f"→ findings → report[/dim]")

    run = AutopilotRun(
        domain=domain, profile=profile,
        started=datetime.now().isoformat(timespec="seconds"))
    skip = set(skip_stages or [])
    started = time.time()

    try:
        if "subs" not in skip:
            _run_subdomain_stage(domain, prof, run)
        if "live" not in skip:
            _run_live_hosts_stage(domain, run)
        if "tech" not in skip:
            _run_tech_stage(run)
        if "ports" not in skip:
            _run_ports_stage(run, prof)
        if "takeover" not in skip:
            _run_takeover_stage(domain, run, prof)
        if "dirbrute" not in skip:
            _run_dir_brute_stage(run, prof)
        if "wayback" not in skip:
            _run_wayback_stage(domain, run, prof)
        if "secrets" not in skip:
            _run_js_secrets_stage(run, prof)
        if "js_ep" not in skip:
            _run_js_endpoints_stage(run, prof)
        if "cors" not in skip:
            _run_cors_stage(run, prof)
        if "graphql" not in skip:
            _run_graphql_stage(run, prof)
        if "findings" not in skip:
            _run_findings_stage(run, domain)
        if "report" not in skip:
            _run_report_stage(run)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Прервано, сохраняю что есть…[/yellow]")
        run.errors.append("interrupted")
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        log.exception("autopilot")
        run.errors.append(str(exc)[:200])

    finished = datetime.now()
    run.finished = finished.isoformat(timespec="seconds")
    run.duration_sec = time.time() - started

    _print_summary(run)
    _notify(run)

    db.save_scan("autopilot", domain, run.summary_dict())
    return run


def _print_summary(run: AutopilotRun) -> None:
    t = Table(title=f"🏁 Autopilot: {run.domain} "
                    f"({run.duration_sec:.1f}s)")
    t.add_column("Метрика", style="cyan")
    t.add_column("Значение", style="green")
    for k, v in run.summary_dict().items():
        if k == "duration":
            continue
        t.add_row(k, str(v))
    t.add_row("errors", str(len(run.errors)))
    console.print(t)
    if run.errors:
        console.print("\n[yellow]Errors:[/yellow]")
        for e in run.errors[:5]:
            console.print(f"  [dim]{e}[/dim]")


# ===========================================================================
# History
# ===========================================================================

def show_past_runs(limit: int = 30) -> None:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT id, target, result, created_at FROM scans "
            "WHERE module='autopilot' ORDER BY id DESC LIMIT ?",
            (limit,))
        rows = cur.fetchall()
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        return
    if not rows:
        console.print("[yellow]Нет запусков.[/yellow]")
        return
    t = Table(title=f"📜 Autopilot runs ({len(rows)})")
    t.add_column("ID", style="cyan", width=5)
    t.add_column("Domain", style="green")
    t.add_column("Subs", width=6)
    t.add_column("Findings", width=8)
    t.add_column("Date", style="white", width=20)
    for r in rows:
        try:
            data = json.loads(r["result"])
        except Exception:
            data = {}
        t.add_row(str(r["id"]), str(r["target"]),
                  str(data.get("subdomains", "?")),
                  str(data.get("findings", "?")),
                  str(r["created_at"])[:19])
    console.print(t)


# ===========================================================================
# CLI / menu
# ===========================================================================

def cli_run(domain: str, profile: str = "full") -> None:
    run_pipeline(domain, profile)


def cli_profiles() -> None:
    t = Table(title="Autopilot profiles")
    t.add_column("Profile", style="cyan")
    t.add_column("Max subs", style="green")
    t.add_column("Dir", width=6)
    t.add_column("Wayback", width=8)
    t.add_column("Secrets", width=8)
    t.add_column("JS-ep", width=8)
    t.add_column("CORS", width=6)
    t.add_column("GraphQL", width=8)
    t.add_column("Takeover", width=10)
    t.add_column("~min", width=6)
    for name, p in PROFILES.items():
        t.add_row(name, str(p["max_subs"]),
                  "✓" if p["dir_brute"] else "—",
                  "✓" if p["wayback"] else "—",
                  "✓" if p["js_secrets"] else "—",
                  "✓" if p["js_endpoints"] else "—",
                  "✓" if p["cors"] else "—",
                  "✓" if p["graphql"] else "—",
                  "✓" if p["takeover"] else "—",
                  str(p["timeout_min"]))
    console.print(t)


def cli_past() -> None:
    show_past_runs()


def menu() -> None:
    t = Table(title="[bold]🎯 Bug Bounty Autopilot[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", "Quick scan (~5 min)"),
        ("2", "Full scan (~30 min)"),
        ("3", "Deep scan (~3 hours)"),
        ("4", "Показать профили"),
        ("5", "История запусков"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованных bug bounty.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        d = Prompt.ask("Домен")
        run_pipeline(d, "quick")
    elif c == "2":
        d = Prompt.ask("Домен")
        run_pipeline(d, "full")
    elif c == "3":
        d = Prompt.ask("Домен")
        if Confirm.ask("Deep scan может занять 3+ часа. Запустить?",
                        default=False):
            run_pipeline(d, "deep")
    elif c == "4":
        cli_profiles()
    elif c == "5":
        cli_past()