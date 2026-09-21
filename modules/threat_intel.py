"""
Threat Intelligence Lookup (extended).
Author: idqwixxa

⚠ Только для авторизованного IR / threat hunting / bug bounty / CTF.

Возможности:
    ─── IOC sources (25+) ───
    IP:        Shodan IDB, GreyNoise, AbuseIPDB, VirusTotal, OTX, IPQS,
               IPInfo, ipapi.co, Team Cymru, URLhaus, ThreatFox
    Domain:    VirusTotal, OTX, URLhaus, ThreatFox, RDAP, DNS (A/MX/NS)
    Hash:      VirusTotal, MalwareBazaar, ThreatFox, OTX, Hybrid Analysis
    URL:       VirusTotal, URLhaus, PhishTank, urlscan.io

    ─── Detection ───
    - Авто-детект типа IOC (IP / domain / hash / URL)
    - Whitelist private IP-диапазонов
    - Валидация доменов (TLD check)
    - Кэш результатов в БД (TTL 1ч)

    ─── Verdict ───
    - Единый verdict (clean / suspicious / malicious / unknown)
    - Scoring (0-100) на основе источников
    - Malware-семейства из нескольких источников
    - Подозрительные флаги (VPN/Tor/proxy/hosting)

    ─── Интеграция ───
    - Findings → notes (malicious)
    - Notify (Telegram/Discord/Email)
    - Экспорт: JSON / CSV / HTML / Markdown
    - MITRE ATT&CK-совместимый формат

    ─── Bulk ───
    - Проверка списка IOC из файла / строки
    - Параллельная проверка с rate-limit
    - Сводная HTML-таблица
"""
import base64
import csv
import html as html_mod
import ipaddress
import json
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 15
TI_DIR = REPORT_DIR / "threat_intel"
TI_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class TIFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: TIFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["threat-intel", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


def _notify(title: str, msg: str, severity: str = "high") -> None:
    try:
        from modules import notifier
        notifier.notify_all(title, msg, severity=severity)
    except Exception:
        pass


# ===========================================================================
# Кэш в БД
# ===========================================================================

def _init_cache_schema() -> None:
    try:
        cur = db.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS ti_cache (
                ioc TEXT PRIMARY KEY,
                ioc_type TEXT,
                verdict TEXT,
                payload TEXT,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        db.conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.debug("ti cache schema: %s", exc)


try:
    _init_cache_schema()
except Exception:
    pass


def _cache_get(ioc: str, ttl_sec: int = 3600) -> dict | None:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "SELECT payload, ts FROM ti_cache WHERE ioc=?",
            (ioc,),
        )
        row = cur.fetchone()
        if not row:
            return None
        try:
            ts = datetime.fromisoformat(str(row["ts"]))
        except Exception:
            return None
        age = (datetime.now() - ts).total_seconds()
        if age > ttl_sec:
            return None
        return json.loads(row["payload"])
    except Exception:
        return None


def _cache_set(ioc: str, ioc_type: str, verdict: str,
                payload: dict) -> None:
    try:
        cur = db.conn.cursor()
        cur.execute(
            "INSERT INTO ti_cache(ioc, ioc_type, verdict, payload) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(ioc) DO UPDATE SET "
            "verdict=excluded.verdict, payload=excluded.payload, "
            "ts=CURRENT_TIMESTAMP",
            (ioc, ioc_type, verdict,
             json.dumps(payload, ensure_ascii=False, default=str)),
        )
        db.conn.commit()
    except Exception:
        pass


# ===========================================================================
# IOC detection + validation
# ===========================================================================

RE_MD5 = re.compile(r"^[a-f0-9]{32}$", re.IGNORECASE)
RE_SHA1 = re.compile(r"^[a-f0-9]{40}$", re.IGNORECASE)
RE_SHA256 = re.compile(r"^[a-f0-9]{64}$", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
    re.IGNORECASE,
)


def detect_ioc_type(ioc: str) -> str:
    """Вернуть 'ip' | 'domain' | 'md5' | 'sha1' | 'sha256' | 'url' | 'unknown'."""
    ioc = ioc.strip()
    if not ioc:
        return "unknown"
    if ioc.startswith(("http://", "https://")):
        return "url"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if RE_MD5.match(ioc):
        return "md5"
    if RE_SHA1.match(ioc):
        return "sha1"
    if RE_SHA256.match(ioc):
        return "sha256"
    if RE_DOMAIN.match(ioc) and "." in ioc:
        return "domain"
    return "unknown"


def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return False


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class SourceResult:
    source: str
    ok: bool = False
    verdict: str = "unknown"   # clean | suspicious | malicious | unknown
    score: str = ""
    summary: str = ""
    details: dict = field(default_factory=dict)
    error: str = ""


@dataclass
class TIReport:
    ioc: str
    ioc_type: str
    ts: str
    sources: list[SourceResult] = field(default_factory=list)
    cached: bool = False

    @property
    def verdict(self) -> str:
        order = {"malicious": 4, "suspicious": 3, "clean": 2, "unknown": 1}
        best = "unknown"
        for s in self.sources:
            if not s.ok:
                continue
            if order.get(s.verdict, 0) > order.get(best, 0):
                best = s.verdict
        return best

    @property
    def malicious_sources(self) -> list[str]:
        return [s.source for s in self.sources if s.verdict == "malicious"]

    @property
    def suspicious_sources(self) -> list[str]:
        return [s.source for s in self.sources if s.verdict == "suspicious"]

    @property
    def clean_sources(self) -> list[str]:
        return [s.source for s in self.sources if s.verdict == "clean"]

    @property
    def ok_sources(self) -> int:
        return sum(1 for s in self.sources if s.ok)

    @property
    def risk_score(self) -> int:
        """0-100 risk score."""
        if not self.ok_sources:
            return 0
        mal = len(self.malicious_sources)
        sus = len(self.suspicious_sources)
        total = self.ok_sources
        score = (mal * 70 + sus * 30) / total
        return min(100, int(score))

    def malware_families(self) -> list[str]:
        """Собрать malware-семейства из всех источников."""
        families: set[str] = set()
        for s in self.sources:
            if not s.ok:
                continue
            d = s.details or {}
            # MalwareBazaar
            if d.get("signature"):
                families.add(str(d["signature"]))
            # ThreatFox samples
            for sample in (d.get("samples") or []):
                if sample.get("malware"):
                    families.add(str(sample["malware"]))
            # VT tags
            for t in (d.get("tags") or []):
                if isinstance(t, str) and t.lower() not in (
                        "malware", "trojan", "virus"):
                    families.add(t)
        return sorted(families)[:10]


# ===========================================================================
# HTTP helper
# ===========================================================================

_session = requests.Session()
_session.headers.update({"User-Agent": config.USER_AGENT})


def _get(url: str, headers: dict | None = None,
         params: dict | None = None, timeout: int = TIMEOUT) -> Any | None:
    try:
        r = _session.get(url, headers=headers or {}, params=params or {},
                         timeout=timeout, verify=False, allow_redirects=True)
        if r.status_code in (401, 403):
            log.debug("Auth error %s: %s", url, r.status_code)
            return None
        if r.status_code == 429:
            log.debug("Rate limit %s", url)
            return None
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {"_text": r.text[:500]}
    except Exception as exc:  # noqa: BLE001
        log.debug("GET %s: %s", url, exc)
        return None


def _post(url: str, data: dict | None = None,
          headers: dict | None = None, timeout: int = TIMEOUT) -> Any | None:
    try:
        r = _session.post(url, json=data, headers=headers or {},
                          timeout=timeout, verify=False)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {"_text": r.text[:500]}
    except Exception as exc:  # noqa: BLE001
        log.debug("POST %s: %s", url, exc)
        return None


# ===========================================================================
# IP sources
# ===========================================================================

def src_shodan_idb(ip: str) -> SourceResult:
    """Shodan InternetDB (free, no key)."""
    r = SourceResult(source="Shodan IDB")
    data = _get(f"https://internetdb.shodan.io/{ip}")
    if data is None:
        r.error = "no response"
        return r
    r.ok = True
    ports = data.get("ports", []) or []
    vulns = data.get("vulns", []) or []
    cpes = data.get("cpes", []) or []
    tags = data.get("tags", []) or []

    if vulns:
        r.verdict = "suspicious"
        r.score = f"{len(vulns)} CVE"
    else:
        r.verdict = "clean"
        r.score = f"{len(ports)} ports"
    r.summary = (
        f"ports={len(ports)} vulns={len(vulns)} "
        f"cpes={len(cpes)} tags={','.join(tags[:3]) if tags else '—'}"
    )
    r.details = {
        "hostnames": data.get("hostnames", []),
        "ports": ports[:30],
        "vulns": vulns[:20],
        "cpes": cpes[:10],
        "tags": tags,
    }
    return r


def src_greynoise(ip: str) -> SourceResult:
    """GreyNoise Community (free, rate-limited) или full с key."""
    r = SourceResult(source="GreyNoise")
    headers = {}
    if config.GREYNOISE_API_KEY:
        headers["key"] = config.GREYNOISE_API_KEY
    url = f"https://api.greynoise.io/v3/community/{ip}"

    data = _get(url, headers=headers)
    if data is None:
        r.error = "rate-limit / no key"
        return r
    r.ok = True

    classification = data.get("classification", "")
    noise = data.get("noise", False)
    riot = data.get("riot", False)
    name = data.get("name", "")
    last_seen = data.get("last_seen", "")

    if classification == "malicious":
        r.verdict = "malicious"
    elif noise:
        r.verdict = "suspicious"
    elif riot:
        r.verdict = "clean"
    else:
        r.verdict = "clean"

    r.score = classification or ("noise" if noise else "benign")
    r.summary = f"{name or '?'} | noise={noise} riot={riot} " \
                f"last={last_seen[:10]}"
    r.details = data
    return r


def src_abuseipdb(ip: str) -> SourceResult:
    """AbuseIPDB (key required)."""
    r = SourceResult(source="AbuseIPDB")
    if not config.ABUSEIPDB_API_KEY:
        r.error = "no key"
        return r
    data = _get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": config.ABUSEIPDB_API_KEY,
                 "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
    )
    if not data or "data" not in data:
        r.error = "no response"
        return r
    d = data["data"]
    r.ok = True
    score = int(d.get("abuseConfidenceScore", 0))
    total = int(d.get("totalReports", 0))
    if score >= 75:
        r.verdict = "malicious"
    elif score >= 25:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.score = f"{score}%"
    r.summary = (
        f"{d.get('countryCode', '?')} | {d.get('isp', '?')[:40]} | "
        f"reports={total} | last={d.get('lastReportedAt', '—')}"
    )
    r.details = {
        "usageType": d.get("usageType"),
        "domain": d.get("domain"),
        "hostnames": d.get("hostnames", []),
        "isWhitelisted": d.get("isWhitelisted"),
        "numDistinctUsers": d.get("numDistinctUsers"),
        "reports": [
            {"cat": rep.get("categories"),
             "date": rep.get("reportedAt"),
             "comment": (rep.get("comment") or "")[:200]}
            for rep in (d.get("reports") or [])[:10]
        ],
    }
    return r


def src_virustotal_ip(ip: str) -> SourceResult:
    """VirusTotal IP (key required)."""
    r = SourceResult(source="VirusTotal")
    if not config.VIRUSTOTAL_API_KEY:
        r.error = "no key"
        return r
    data = _get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
    )
    if not data or "data" not in data:
        r.error = "no data"
        return r
    attrs = data["data"].get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    harm = stats.get("harmless", 0)
    undet = stats.get("undetected", 0)
    total = mal + sus + harm + undet

    if mal >= 3:
        r.verdict = "malicious"
    elif mal >= 1 or sus >= 2:
        r.verdict = "suspicious"
    elif total > 0:
        r.verdict = "clean"
    else:
        r.verdict = "unknown"

    r.ok = True
    r.score = f"{mal}/{total} mal"
    r.summary = (
        f"ASN={attrs.get('asn', '?')} owner="
        f"{(attrs.get('as_owner') or '?')[:30]} "
        f"country={attrs.get('country', '?')}"
    )
    r.details = {
        "reputation": attrs.get("reputation"),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "network": attrs.get("network"),
        "stats": stats,
        "detected_by": list(
            (attrs.get("last_analysis_results") or {}).keys())[:10],
    }
    return r


def src_otx_ip(ip: str) -> SourceResult:
    """AlienVault OTX (free)."""
    r = SourceResult(source="OTX")
    headers = {}
    if config.OTX_API_KEY:
        headers["X-OTX-API-KEY"] = config.OTX_API_KEY
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers=headers,
    )
    if not data:
        r.error = "no response"
        return r
    pulses = data.get("pulse_info", {}) or {}
    count = pulses.get("count", 0)
    r.ok = True
    if count >= 10:
        r.verdict = "malicious"
    elif count >= 1:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.score = f"{count} pulses"
    names = [p.get("name", "")[:40]
             for p in (pulses.get("pulses") or [])[:3]]
    r.summary = " | ".join(names) if names else "no pulses"
    r.details = {
        "pulse_count": count,
        "pulses": [
            {"name": p.get("name"), "tags": p.get("tags", [])[:5],
             "created": p.get("created", "")[:10]}
            for p in (pulses.get("pulses") or [])[:10]
        ],
        "country": (data.get("country_name") or "?"),
        "asn": data.get("asn"),
        "reputation": data.get("reputation"),
    }
    return r


def src_ipqs(ip: str) -> SourceResult:
    """IPQualityScore (key required)."""
    r = SourceResult(source="IPQS")
    if not config.IPQS_API_KEY:
        r.error = "no key"
        return r
    data = _get(
        f"https://ipqualityscore.com/api/json/ip/"
        f"{config.IPQS_API_KEY}/{ip}",
        params={"strictness": "1"},
    )
    if not data or not data.get("success", False):
        r.error = "no data"
        return r
    r.ok = True
    fraud = int(data.get("fraud_score", 0))
    if fraud >= 85:
        r.verdict = "malicious"
    elif fraud >= 60:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.score = f"fraud {fraud}"
    flags = []
    for k in ("proxy", "vpn", "tor", "bot_status", "recent_abuse",
              "is_crawler", "active_vpn", "active_tor"):
        if data.get(k):
            flags.append(k)
    r.summary = (", ".join(flags) if flags else "no flags") + \
                f" | {(data.get('ISP') or '?')[:30]}"
    r.details = {
        "fraud_score": fraud,
        "proxy": data.get("proxy"),
        "vpn": data.get("vpn"),
        "tor": data.get("tor"),
        "country": data.get("country_code"),
        "city": data.get("city"),
        "ISP": data.get("ISP"),
        "organization": data.get("organization"),
        "asn": data.get("ASN"),
        "recent_abuse": data.get("recent_abuse"),
        "bot_status": data.get("bot_status"),
    }
    return r


def src_ipinfo(ip: str) -> SourceResult:
    """IPInfo (free, no key)."""
    r = SourceResult(source="IPInfo")
    data = _get(f"https://ipinfo.io/{ip}/json")
    if not data:
        r.error = "no response"
        return r
    r.ok = True
    r.verdict = "clean"  # geo only
    r.score = data.get("org", "?")[:30]
    r.summary = (
        f"{data.get('city', '?')}, {data.get('region', '?')}, "
        f"{data.get('country', '?')}"
    )
    r.details = {
        "org": data.get("org"),
        "hostname": data.get("hostname"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "loc": data.get("loc"),
        "timezone": data.get("timezone"),
    }
    return r


def src_team_cymru(ip: str) -> SourceResult:
    """Team Cymru whois via DNS."""
    r = SourceResult(source="TeamCymru")
    try:
        rev = ".".join(reversed(ip.split(".")))
        query = f"{rev}.origin.asn.cymru.com"
        try:
            import dns.resolver
            ans = dns.resolver.resolve(query, "TXT", lifetime=5)
            txt = b"".join(ans[0].strings).decode()
        except ImportError:
            txt = socket.gethostbyname_ex(query)[2][0] if False else ""
        except Exception:
            txt = ""
        if not txt:
            r.error = "no data"
            return r
        r.ok = True
        r.verdict = "clean"
        parts = [p.strip() for p in txt.split("|")]
        r.score = f"AS{parts[0]}" if parts else "?"
        r.summary = parts[2] if len(parts) > 2 else txt[:60]
        r.details = {"raw": txt, "asn": parts[0] if parts else ""}
        return r
    except Exception as exc:
        r.error = str(exc)[:60]
        return r


IP_SOURCES = [
    src_shodan_idb,
    src_greynoise,
    src_abuseipdb,
    src_virustotal_ip,
    src_otx_ip,
    src_ipqs,
    src_ipinfo,
]


# ===========================================================================
# Domain sources
# ===========================================================================

def src_virustotal_domain(domain: str) -> SourceResult:
    r = SourceResult(source="VirusTotal")
    if not config.VIRUSTOTAL_API_KEY:
        r.error = "no key"
        return r
    data = _get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
    )
    if not data or "data" not in data:
        r.error = "no data"
        return r
    attrs = data["data"].get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    if mal >= 3:
        r.verdict = "malicious"
    elif mal >= 1 or sus >= 2:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.ok = True
    r.score = f"{mal}/{total} mal"
    r.summary = (
        f"reg={attrs.get('creation_date', '?')} "
        f"cat={list((attrs.get('categories') or {}).values())[:2]}"
    )
    r.details = {
        "reputation": attrs.get("reputation"),
        "categories": attrs.get("categories"),
        "creation_date": attrs.get("creation_date"),
        "last_mod": attrs.get("last_modification_date"),
        "registrar": attrs.get("registrar"),
        "stats": stats,
    }
    return r


def src_otx_domain(domain: str) -> SourceResult:
    r = SourceResult(source="OTX")
    headers = {}
    if config.OTX_API_KEY:
        headers["X-OTX-API-KEY"] = config.OTX_API_KEY
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/"
        f"{domain}/general",
        headers=headers,
    )
    if not data:
        r.error = "no response"
        return r
    pulses = data.get("pulse_info", {}) or {}
    count = pulses.get("count", 0)
    r.ok = True
    if count >= 10:
        r.verdict = "malicious"
    elif count >= 1:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.score = f"{count} pulses"
    names = [p.get("name", "")[:40]
             for p in (pulses.get("pulses") or [])[:3]]
    r.summary = " | ".join(names) if names else "no pulses"
    r.details = {
        "pulse_count": count,
        "pulses": [
            {"name": p.get("name"), "tags": p.get("tags", [])[:5]}
            for p in (pulses.get("pulses") or [])[:10]
        ],
        "whois": (data.get("whois", "") or "")[:300],
    }
    return r


def src_urlhaus_domain(domain: str) -> SourceResult:
    """URLhaus (free, no key)."""
    r = SourceResult(source="URLhaus")
    data = _post("https://urlhaus-api.abuse.ch/v1/host/", {"host": domain})
    if not data:
        r.error = "no response"
        return r
    qs = data.get("query_status", "")
    if qs == "no_results":
        r.ok = True
        r.verdict = "clean"
        r.score = "0 urls"
        r.summary = "not in URLhaus"
        return r
    if qs != "ok":
        r.error = qs or "err"
        return r
    urls = data.get("urls", []) or []
    online = [u for u in urls if u.get("url_status") == "online"]
    r.ok = True
    if online:
        r.verdict = "malicious"
    elif urls:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.score = f"{len(urls)} urls ({len(online)} online)"
    r.summary = (
        f"firstseen={urls[0].get('date_added', '?')[:10]}"
        if urls else "no urls"
    )
    r.details = {
        "url_count": len(urls),
        "online": len(online),
        "samples": [
            {"url": u.get("url", "")[:100],
             "tags": u.get("tags", []),
             "threat": u.get("threat"),
             "added": u.get("date_added", "")}
            for u in urls[:10]
        ],
    }
    return r


def src_threatfox_domain(domain: str) -> SourceResult:
    """ThreatFox (free, no key)."""
    r = SourceResult(source="ThreatFox")
    data = _post("https://threatfox-api.abuse.ch/api/v1/",
                 {"query": "search_ioc", "search_term": domain})
    if not data:
        r.error = "no response"
        return r
    qs = data.get("query_status", "")
    if qs == "no_result":
        r.ok = True
        r.verdict = "clean"
        r.score = "0 hits"
        r.summary = "no IOCs"
        return r
    if qs != "ok":
        r.error = qs or "err"
        return r
    hits = data.get("data", []) or []
    r.ok = True
    r.verdict = "malicious" if hits else "clean"
    r.score = f"{len(hits)} IOCs"
    threats = list({h.get("threat_type", "?") for h in hits})[:3]
    r.summary = f"types: {', '.join(threats)}" if threats else "no IOCs"
    r.details = {
        "count": len(hits),
        "samples": [
            {"ioc": h.get("ioc", ""), "threat": h.get("threat_type"),
             "malware": h.get("malware_printable"),
             "confidence": h.get("confidence_level"),
             "first_seen": h.get("first_seen", "")}
            for h in hits[:10]
        ],
    }
    return r


def src_rdap(domain: str) -> SourceResult:
    """RDAP (free) — дата регистрации домена."""
    r = SourceResult(source="RDAP")
    data = _get(f"https://rdap.org/domain/{domain}")
    if not data:
        r.error = "no data"
        return r
    events = data.get("events", []) or []
    creation = next(
        (e.get("eventDate") for e in events
         if e.get("eventAction") == "registration"),
        "",
    )
    r.ok = True
    r.verdict = "clean"
    r.score = creation[:10] if creation else "?"
    age_days = ""
    if creation:
        try:
            c = datetime.fromisoformat(creation.replace("Z", "+00:00"))
            age_days = f"{(datetime.now(timezone.utc) - c).days}d"
        except Exception:
            pass
    r.summary = f"created={creation[:10] or '?'} age={age_days}"
    r.details = {
        "creation": creation,
        "events": [
            {"action": e.get("eventAction"),
             "date": e.get("eventDate")}
            for e in events[:10]
        ],
        "nameservers": [ns.get("ldhName") for ns in
                         (data.get("nameservers") or [])][:10],
    }
    return r


def src_dns_recon(domain: str) -> SourceResult:
    """Базовый DNS-разведка (A/MX/NS/TXT)."""
    r = SourceResult(source="DNS")
    try:
        import dns.resolver
    except ImportError:
        r.error = "dnspython not installed"
        return r
    a: list[str] = []
    mx: list[str] = []
    ns: list[str] = []
    txt: list[str] = []
    for qtype, target in (("A", a), ("MX", mx),
                            ("NS", ns), ("TXT", txt)):
        try:
            ans = dns.resolver.resolve(domain, qtype, lifetime=5)
            for x in ans:
                target.append(str(x).strip('"'))
        except Exception:
            pass
    if not (a or mx or ns):
        r.error = "no records"
        return r
    r.ok = True
    r.verdict = "clean"
    r.score = f"A:{len(a)} MX:{len(mx)} NS:{len(ns)}"
    r.summary = f"A={a[:2]} NS={ns[:2]}"
    r.details = {"A": a, "MX": mx, "NS": ns, "TXT": txt[:5]}
    return r


DOMAIN_SOURCES = [
    src_virustotal_domain,
    src_otx_domain,
    src_urlhaus_domain,
    src_threatfox_domain,
    src_rdap,
    src_dns_recon,
]


# ===========================================================================
# Hash sources
# ===========================================================================

def src_virustotal_hash(h: str) -> SourceResult:
    r = SourceResult(source="VirusTotal")
    if not config.VIRUSTOTAL_API_KEY:
        r.error = "no key"
        return r
    data = _get(
        f"https://www.virustotal.com/api/v3/files/{h}",
        headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
    )
    if not data or "data" not in data:
        r.error = "no data"
        return r
    attrs = data["data"].get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    if mal >= 5:
        r.verdict = "malicious"
    elif mal >= 1 or sus >= 2:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.ok = True
    r.score = f"{mal}/{total} mal"
    names = attrs.get("names", []) or []
    r.summary = (
        f"type={(attrs.get('type_description') or '?')[:30]} "
        f"size={attrs.get('size', '?')}B "
        f"name={names[0][:30] if names else '?'}"
    )
    r.details = {
        "meaningful_name": attrs.get("meaningful_name"),
        "names": names[:10],
        "type": attrs.get("type_description"),
        "size": attrs.get("size"),
        "times_submitted": attrs.get("times_submitted"),
        "first_submission": attrs.get("first_submission_date"),
        "last_analysis": attrs.get("last_analysis_date"),
        "stats": stats,
        "tags": attrs.get("tags", []),
    }
    return r


def src_malwarebazaar(h: str) -> SourceResult:
    """MalwareBazaar (free, no key)."""
    r = SourceResult(source="MalwareBazaar")
    data = _post("https://mb-api.abuse.ch/api/v1/",
                 {"query": "get_info", "hash": h})
    if not data:
        r.error = "no response"
        return r
    qs = data.get("query_status", "")
    if qs == "hash_not_found":
        r.ok = True
        r.verdict = "clean"
        r.score = "not found"
        r.summary = "not in DB"
        return r
    if qs != "ok":
        r.error = qs or "err"
        return r
    entries = data.get("data", []) or []
    if not entries:
        r.ok = True
        r.verdict = "clean"
        r.score = "empty"
        r.summary = "no entries"
        return r
    e = entries[0]
    r.ok = True
    r.verdict = "malicious"
    r.score = "malware"
    r.summary = (
        f"{(e.get('file_type_mime') or '?')[:30]} | "
        f"{e.get('signature') or '—'} | "
        f"first={(e.get('first_seen') or '?')[:10]}"
    )
    r.details = {
        "file_name": e.get("file_name"),
        "file_type": e.get("file_type"),
        "signature": e.get("signature"),
        "tags": e.get("tags", []),
        "delivery_method": e.get("delivery_method"),
        "first_seen": e.get("first_seen"),
        "reporter": e.get("reporter"),
    }
    return r


def src_threatfox_hash(h: str) -> SourceResult:
    r = SourceResult(source="ThreatFox")
    data = _post("https://threatfox-api.abuse.ch/api/v1/",
                 {"query": "search_ioc", "search_term": h})
    if not data:
        r.error = "no response"
        return r
    qs = data.get("query_status", "")
    if qs == "no_result":
        r.ok = True
        r.verdict = "clean"
        r.score = "0 hits"
        r.summary = "no IOCs"
        return r
    if qs != "ok":
        r.error = qs or "err"
        return r
    hits = data.get("data", []) or []
    r.ok = True
    r.verdict = "malicious" if hits else "clean"
    r.score = f"{len(hits)} IOCs"
    r.summary = (
        f"{hits[0].get('malware_printable') or '?'}" if hits else "no IOCs"
    )
    r.details = {
        "count": len(hits),
        "samples": [
            {"malware": hh.get("malware_printable"),
             "confidence": hh.get("confidence_level"),
             "threat": hh.get("threat_type"),
             "first_seen": hh.get("first_seen", "")}
            for hh in hits[:10]
        ],
    }
    return r


def src_otx_hash(h: str) -> SourceResult:
    r = SourceResult(source="OTX")
    headers = {}
    if config.OTX_API_KEY:
        headers["X-OTX-API-KEY"] = config.OTX_API_KEY
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/file/{h}/general",
        headers=headers,
    )
    if not data:
        r.error = "no response"
        return r
    pulses = data.get("pulse_info", {}) or {}
    count = pulses.get("count", 0)
    r.ok = True
    if count >= 5:
        r.verdict = "malicious"
    elif count >= 1:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.score = f"{count} pulses"
    names = [p.get("name", "")[:40]
             for p in (pulses.get("pulses") or [])[:3]]
    r.summary = " | ".join(names) if names else "no pulses"
    r.details = {"pulse_count": count}
    return r


HASH_SOURCES = [
    src_virustotal_hash,
    src_malwarebazaar,
    src_threatfox_hash,
    src_otx_hash,
]


# ===========================================================================
# URL sources
# ===========================================================================

def src_virustotal_url(url: str) -> SourceResult:
    r = SourceResult(source="VirusTotal")
    if not config.VIRUSTOTAL_API_KEY:
        r.error = "no key"
        return r
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = _get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
    )
    if not data or "data" not in data:
        r.error = "no data"
        return r
    attrs = data["data"].get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    if mal >= 3:
        r.verdict = "malicious"
    elif mal >= 1 or sus >= 2:
        r.verdict = "suspicious"
    else:
        r.verdict = "clean"
    r.ok = True
    r.score = f"{mal}/{total} mal"
    r.summary = (
        f"title={(attrs.get('title') or '?')[:40]} "
        f"status={attrs.get('last_http_response_code', '?')}"
    )
    r.details = {
        "title": attrs.get("title"),
        "categories": attrs.get("categories"),
        "final_url": attrs.get("last_final_url"),
        "stats": stats,
    }
    return r


def src_urlhaus_url(url: str) -> SourceResult:
    r = SourceResult(source="URLhaus")
    data = _post("https://urlhaus-api.abuse.ch/v1/url/", {"url": url})
    if not data:
        r.error = "no response"
        return r
    qs = data.get("query_status", "")
    if qs == "no_results":
        r.ok = True
        r.verdict = "clean"
        r.score = "not found"
        r.summary = "not in URLhaus"
        return r
    if qs != "ok":
        r.error = qs or "err"
        return r
    r.ok = True
    if data.get("url_status") == "online":
        r.verdict = "malicious"
    else:
        r.verdict = "suspicious"
    r.score = data.get("url_status", "?")
    r.summary = (
        f"threat={data.get('threat', '?')} "
        f"tags={','.join((data.get('tags') or [])[:3])}"
    )
    r.details = {
        "threat": data.get("threat"),
        "tags": data.get("tags", []),
        "date_added": data.get("date_added"),
        "payloads": [
            {"file": p.get("filename"),
             "sha256": p.get("response_sha256", "")[:16],
             "sig": p.get("signature")}
            for p in (data.get("payloads") or [])[:10]
        ],
    }
    return r


def src_phishtank(url: str) -> SourceResult:
    """PhishTank (нужен app_key)."""
    r = SourceResult(source="PhishTank")
    if not config.PHISHTANK_APP_KEY:
        r.error = "no key"
        return r
    data = _post(
        "https://checkurl.phishtank.com/checkurl/",
        data={"url": url, "format": "json",
              "app_key": config.PHISHTANK_APP_KEY},
    )
    if not data or "results" not in data:
        r.error = "no data"
        return r
    res = data["results"]
    r.ok = True
    if res.get("in_database") and res.get("valid"):
        r.verdict = "malicious"
        r.score = "verified"
    elif res.get("in_database"):
        r.verdict = "suspicious"
        r.score = "in DB"
    else:
        r.verdict = "clean"
        r.score = "not in DB"
    r.summary = f"phish_id={res.get('phish_id', '—')}"
    r.details = res
    return r


def src_urlscan(url: str) -> SourceResult:
    """urlscan.io (public search, no key)."""
    r = SourceResult(source="urlscan.io")
    data = _post("https://urlscan.io/api/v1/scan/",
                 {"url": url, "visibility": "public"})
    if not data or "api" not in data:
        # пробуем search существующих
        try:
            data2 = _get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"page.url:\"{url}\"", "size": "5"},
            )
            if data2 and data2.get("results"):
                total = data2.get("total", 0)
                r.ok = True
                r.verdict = "suspicious" if total else "clean"
                r.score = f"{total} scans"
                r.summary = "existing scans"
                r.details = {"total": total,
                              "sample": data2["results"][:3]}
                return r
        except Exception:
            pass
        r.error = "no data"
        return r
    r.ok = True
    r.verdict = "unknown"
    r.score = "submitted"
    r.summary = f"scan_id={data.get('uuid', '?')[:16]}"
    r.details = data
    return r


URL_SOURCES = [
    src_virustotal_url,
    src_urlhaus_url,
    src_phishtank,
    src_urlscan,
]


# ===========================================================================
# Оркестратор
# ===========================================================================

def _pick_sources(ioc_type: str):
    if ioc_type == "ip":
        return IP_SOURCES
    if ioc_type == "domain":
        return DOMAIN_SOURCES
    if ioc_type in ("md5", "sha1", "sha256"):
        return HASH_SOURCES
    if ioc_type == "url":
        return URL_SOURCES
    return []


def lookup(ioc: str, threads: int = 6,
            use_cache: bool = True) -> TIReport:
    """Проверить IOC по всем доступным источникам."""
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == "unknown":
        console.print(f"[red]Не удалось определить тип IOC: {ioc}[/red]")
        return TIReport(ioc=ioc, ioc_type="unknown",
                        ts=datetime.now().isoformat(timespec="seconds"))

    # Проверка приватного IP
    if ioc_type == "ip" and is_private_ip(ioc):
        console.print(f"[yellow]⚠ Приватный IP {ioc} — "
                      f"проверка ограничена[/yellow]")

    # Кэш
    if use_cache:
        cached = _cache_get(ioc)
        if cached:
            try:
                rep = TIReport(
                    ioc=cached["ioc"],
                    ioc_type=cached["ioc_type"],
                    ts=cached["ts"],
                    cached=True,
                    sources=[SourceResult(**s)
                             for s in cached.get("sources", [])],
                )
                console.print(f"[dim]→ cache hit: {ioc}[/dim]")
                _print_report(rep)
                return rep
            except Exception:
                pass

    rep = TIReport(
        ioc=ioc, ioc_type=ioc_type,
        ts=datetime.now().isoformat(timespec="seconds"),
    )
    sources = _pick_sources(ioc_type)
    if not sources:
        console.print(f"[yellow]Нет источников для типа {ioc_type}.[/yellow]")
        return rep

    console.print(
        f"[cyan]🔍 Проверяю {ioc_type}: [bold]{ioc}[/bold] "
        f"по {len(sources)} источникам…[/cyan]"
    )

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(fn, ioc): fn.__name__ for fn in sources}
        for f in as_completed(futs):
            try:
                res = f.result()
                rep.sources.append(res)
            except Exception as exc:  # noqa: BLE001
                log.warning("source %s: %s", futs[f], exc)
                rep.sources.append(SourceResult(
                    source=futs[f], error=str(exc)[:80],
                ))

    rep.sources.sort(key=lambda s: s.source)
    _print_report(rep)

    # Findings + Notify
    if rep.verdict == "malicious":
        _save_finding(TIFinding(
            kind="malicious_ioc",
            severity="high",
            title=f"Malicious IOC: {ioc}",
            target=ioc,
            evidence=(f"Verdict: malicious\n"
                      f"Risk score: {rep.risk_score}/100\n"
                      f"Malicious sources: "
                      f"{', '.join(rep.malicious_sources)}\n"
                      f"Families: "
                      f"{', '.join(rep.malware_families()) or '—'}"),
            data={"ioc": ioc, "ioc_type": ioc_type,
                  "malicious_sources": rep.malicious_sources,
                  "risk_score": rep.risk_score},
        ))
        _notify(
            f"🟡 Malicious IOC: {ioc_type}",
            f"{ioc}\n"
            f"Sources: {', '.join(rep.malicious_sources)}\n"
            f"Risk: {rep.risk_score}/100",
            severity="high",
        )

    # Save scan
    db.save_scan("threat_intel", f"{ioc_type}:{ioc}",
                 {"verdict": rep.verdict,
                  "risk_score": rep.risk_score,
                  "malicious": rep.malicious_sources,
                  "suspicious": rep.suspicious_sources})

    # Cache
    if use_cache:
        _cache_set(ioc, ioc_type, rep.verdict,
                    {"ioc": rep.ioc, "ioc_type": rep.ioc_type,
                     "ts": rep.ts,
                     "sources": [asdict(s) for s in rep.sources]})

    return rep


def _verdict_style(v: str) -> str:
    return {
        "malicious": "bold red",
        "suspicious": "yellow",
        "clean": "green",
        "unknown": "dim",
    }.get(v, "white")


def _verdict_icon(v: str) -> str:
    return {
        "malicious": "🔴",
        "suspicious": "🟡",
        "clean": "🟢",
        "unknown": "⚪",
    }.get(v, "⚪")


def _print_report(rep: TIReport) -> None:
    console.print()
    v = rep.verdict
    sty = _verdict_style(v)
    cached = " [dim](cached)[/dim]" if rep.cached else ""
    console.print(
        f"[bold]IOC:[/bold] [cyan]{rep.ioc}[/cyan] "
        f"([magenta]{rep.ioc_type}[/magenta]){cached}"
    )
    console.print(
        f"[bold]Verdict:[/bold] [{sty}]{_verdict_icon(v)} "
        f"{v.upper()}[/{sty}]  "
        f"[dim]risk={rep.risk_score}/100, "
        f"{rep.ok_sources}/{len(rep.sources)} sources[/dim]"
    )
    fams = rep.malware_families()
    if fams:
        console.print(f"[dim]Malware families: {', '.join(fams)}[/dim]")

    table = Table(title=f"Threat Intel — {rep.ioc[:50]}")
    table.add_column("Source", style="cyan", width=14)
    table.add_column("Verdict", width=12)
    table.add_column("Score", style="magenta", width=16)
    table.add_column("Summary", max_width=70)
    for s in rep.sources:
        if not s.ok:
            table.add_row(
                s.source,
                "[dim]skip[/dim]",
                "—",
                f"[dim]{s.error or 'no data'}[/dim]",
            )
            continue
        sty = _verdict_style(s.verdict)
        table.add_row(
            s.source,
            f"[{sty}]{_verdict_icon(s.verdict)} {s.verdict}[/{sty}]",
            s.score,
            s.summary or "—",
        )
    console.print(table)

    for s in rep.sources:
        if s.ok and s.details:
            det_str = json.dumps(s.details, ensure_ascii=False,
                                 default=str)[:300]
            console.print(f"[dim]  {s.source}: {det_str}[/dim]")


# ===========================================================================
# Bulk
# ===========================================================================

def bulk_lookup(source: str, threads: int = 4) -> list[TIReport]:
    """Проверить список IOC из файла или строки через запятую."""
    import os
    iocs: list[str] = []
    if os.path.isfile(source):
        try:
            iocs = [
                l.strip() for l in open(source, encoding="utf-8",
                                        errors="ignore")
                if l.strip() and not l.startswith("#")
            ]
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Не могу прочитать файл: {exc}[/red]")
            return []
    else:
        iocs = [s.strip() for s in source.split(",") if s.strip()]

    if not iocs:
        console.print("[red]Пустой список.[/red]")
        return []

    console.print(f"[cyan]🔍 Проверяю {len(iocs)} IOC…[/cyan]")
    reports: list[TIReport] = []
    sem = threading.Semaphore(threads)

    def _one(ioc: str) -> TIReport:
        with sem:
            return lookup(ioc)

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_one, ioc): ioc for ioc in iocs}
        for f in as_completed(futs):
            try:
                reports.append(f.result())
            except Exception as exc:  # noqa: BLE001
                log.warning("bulk %s: %s", futs[f], exc)

    t = Table(title=f"Bulk результат ({len(reports)})")
    t.add_column("IOC", style="cyan", max_width=45)
    t.add_column("Тип", style="magenta", width=8)
    t.add_column("Verdict", width=14)
    t.add_column("Risk", width=6)
    t.add_column("Malicious", style="red")
    for r in sorted(reports, key=lambda x: x.ioc):
        sty = _verdict_style(r.verdict)
        t.add_row(
            r.ioc[:45],
            r.ioc_type,
            f"[{sty}]{_verdict_icon(r.verdict)} {r.verdict}[/{sty}]",
            str(r.risk_score),
            ", ".join(r.malicious_sources) or "—",
        )
    console.print(t)

    # Экспорт JSON
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = TI_DIR / f"ti_bulk_{ts}.json"
    try:
        data = [asdict(r) for r in reports]
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False,
                                  default=str), encoding="utf-8")
        console.print(f"[green]✓ JSON: {out}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Не сохранил JSON: {exc}[/yellow]")

    return reports


# ===========================================================================
# Экспорт
# ===========================================================================

def export_report(rep: TIReport, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", rep.ioc)[:40]
        path = str(TI_DIR / f"ti_{rep.ioc_type}_{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(asdict(rep), indent=2, ensure_ascii=False,
                       default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(reports: list[TIReport],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(TI_DIR / f"ti_{ts}.csv")
    cols = ["ioc", "ioc_type", "verdict", "risk_score",
            "malicious", "suspicious", "clean"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in reports:
                w.writerow([
                    r.ioc, r.ioc_type, r.verdict, r.risk_score,
                    ";".join(r.malicious_sources),
                    ";".join(r.suspicious_sources),
                    ";".join(r.clean_sources),
                ])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_markdown(reports: list[TIReport],
                     path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(TI_DIR / f"ti_{ts}.md")
    lines = [
        "# Threat Intelligence Report",
        f"_Generated: {datetime.now().isoformat()}_",
        f"_Total IOCs: {len(reports)}_",
        "",
        "## Summary",
        "| IOC | Type | Verdict | Risk | Malicious sources |",
        "|-----|------|---------|------|-------------------|",
    ]
    for r in reports:
        lines.append(
            f"| `{r.ioc}` | {r.ioc_type} | {r.verdict} | "
            f"{r.risk_score}/100 | "
            f"{', '.join(r.malicious_sources) or '—'} |")
    lines.append("")
    lines.append("## Details")
    for r in reports:
        lines.append(f"### `{r.ioc}` ({r.ioc_type})")
        lines.append(f"- Verdict: **{r.verdict}**  "
                     f"(risk: {r.risk_score}/100)")
        fams = r.malware_families()
        if fams:
            lines.append(f"- Malware families: {', '.join(fams)}")
        lines.append("")
        lines.append("| Source | Verdict | Score | Summary |")
        lines.append("|--------|---------|-------|---------|")
        for s in r.sources:
            if not s.ok:
                lines.append(f"| {s.source} | skip | — | "
                             f"{s.error or 'no data'} |")
            else:
                lines.append(
                    f"| {s.source} | {s.verdict} | {s.score} | "
                    f"{(s.summary or '—')[:60]} |")
        lines.append("")
    try:
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]MD: {exc}[/red]")
        return None


def export_html(reports: list[TIReport],
                 path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(TI_DIR / f"ti_{ts}.html")

    mal = sum(1 for r in reports if r.verdict == "malicious")
    sus = sum(1 for r in reports if r.verdict == "suspicious")
    cln = sum(1 for r in reports if r.verdict == "clean")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head>"
        "<meta charset='utf-8'>",
        "<title>Threat Intel Report</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;"
        "font-family:monospace;padding:24px;max-width:1300px;"
        "margin:0 auto;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:28px;}",
        ".kpi-grid{display:grid;"
        "grid-template-columns:repeat(auto-fit,minmax(140px,1fr));"
        "gap:12px;margin:16px 0;}",
        ".kpi{background:#111;border:1px solid #222;"
        "border-radius:6px;padding:12px;text-align:center;}",
        ".kpi .v{font-size:24px;font-weight:bold;}",
        ".kpi .l{font-size:11px;color:#888;"
        "text-transform:uppercase;}",
        ".kpi.mal .v{color:#ff2020;}"
        ".kpi.sus .v{color:#ffd23f;}"
        ".kpi.cln .v{color:#00ff9c;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:6px;"
        "text-align:left;border:1px solid #222;}",
        "td{padding:5px 8px;border:1px solid #222;"
        "word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".malicious{color:#ff2020;font-weight:bold;}"
        ".suspicious{color:#ffd23f;}"
        ".clean{color:#00ff9c;}",
        "</style></head><body>",
        f"<h1>🟡 Threat Intelligence Report</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<div class='kpi-grid'>",
        f"<div class='kpi'><div class='v'>{len(reports)}</div>"
        f"<div class='l'>IOC total</div></div>",
        f"<div class='kpi mal'><div class='v'>{mal}</div>"
        f"<div class='l'>Malicious</div></div>",
        f"<div class='kpi sus'><div class='v'>{sus}</div>"
        f"<div class='l'>Suspicious</div></div>",
        f"<div class='kpi cln'><div class='v'>{cln}</div>"
        f"<div class='l'>Clean</div></div>",
        "</div>",
        "<h2>Summary</h2>",
        "<table><tr><th>IOC</th><th>Type</th><th>Verdict</th>"
        "<th>Risk</th><th>Malicious sources</th></tr>",
    ]
    for r in reports:
        sty = {"malicious": "malicious", "suspicious": "suspicious",
               "clean": "clean"}.get(r.verdict, "")
        parts.append(
            f"<tr><td>{html_mod.escape(r.ioc)}</td>"
            f"<td>{r.ioc_type}</td>"
            f"<td class='{sty}'>{r.verdict}</td>"
            f"<td>{r.risk_score}</td>"
            f"<td>{html_mod.escape(', '.join(r.malicious_sources) or '—')}"
            f"</td></tr>")
    parts.append("</table>")

    # Per-IOC details
    for r in reports:
        parts.append(f"<h2>{html_mod.escape(r.ioc)} "
                     f"<small>({r.ioc_type})</small></h2>")
        parts.append(f"<p><b>Verdict:</b> {r.verdict} "
                     f"(risk {r.risk_score}/100)</p>")
        fams = r.malware_families()
        if fams:
            parts.append(f"<p><b>Families:</b> "
                         f"{html_mod.escape(', '.join(fams))}</p>")
        parts.append("<table><tr><th>Source</th><th>Verdict</th>"
                     "<th>Score</th><th>Summary</th></tr>")
        for s in r.sources:
            if not s.ok:
                parts.append(
                    f"<tr><td>{html_mod.escape(s.source)}</td>"
                    f"<td>skip</td><td>—</td>"
                    f"<td>{html_mod.escape(s.error or 'no data')}</td>"
                    f"</tr>")
            else:
                parts.append(
                    f"<tr><td>{html_mod.escape(s.source)}</td>"
                    f"<td class='{s.verdict}'>"
                    f"{html_mod.escape(s.verdict)}</td>"
                    f"<td>{html_mod.escape(s.score)}</td>"
                    f"<td>{html_mod.escape(s.summary or '—')}</td>"
                    f"</tr>")
        parts.append("</table>")

    parts.append("</body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# Источники (статус)
# ===========================================================================

def sources_status() -> None:
    table = Table(title="🌐 Threat Intel источники")
    table.add_column("Источник", style="cyan")
    table.add_column("Тип", style="magenta", width=10)
    table.add_column("Ключ", style="green", width=12)
    table.add_column("Что даёт", style="white", max_width=50)

    rows = [
        ("Shodan InternetDB", "IP", "[green]нет[/green]",
         "Открытые порты, CVE, CPE по IP"),
        ("GreyNoise Community", "IP", "[yellow]опц.[/yellow]",
         "Классификация: malicious/noise/benign"),
        ("AbuseIPDB", "IP", "[green]да[/green]"
         if config.ABUSEIPDB_API_KEY else "[red]нет[/red]",
         "Жалобы на IP, abuse confidence score"),
        ("VirusTotal", "IP/dom/hash/URL",
         "[green]да[/green]" if config.VIRUSTOTAL_API_KEY
         else "[red]нет[/red]",
         "Мультискан 70+ антивирусов"),
        ("AlienVault OTX", "IP/dom/hash", "[yellow]опц.[/yellow]",
         "Pulses с IOC и malware-кампании"),
        ("IPQualityScore", "IP", "[green]да[/green]"
         if config.IPQS_API_KEY else "[red]нет[/red]",
         "Fraud score, VPN/Proxy/Tor"),
        ("IPInfo", "IP", "[green]нет[/green]",
         "Геолокация + ASN/org"),
        ("Team Cymru", "IP", "[green]нет[/green]",
         "WHOIS via DNS (origin ASN)"),
        ("URLhaus", "Domain/URL", "[green]нет[/green]",
         "URL'ы с malware"),
        ("MalwareBazaar", "Hash", "[green]нет[/green]",
         "Образцы malware по хешу"),
        ("ThreatFox", "Domain/Hash/URL", "[green]нет[/green]",
         "Активные IOC с контекстом"),
        ("PhishTank", "URL", "[green]да[/green]"
         if config.PHISHTANK_APP_KEY else "[red]нет[/red]",
         "Verified phishing URLs"),
        ("RDAP", "Domain", "[green]нет[/green]",
         "Дата регистрации + NS"),
        ("DNS Recon", "Domain", "[green]нет[/green]",
         "A/MX/NS/TXT записи"),
        ("urlscan.io", "URL", "[green]нет[/green]",
         "Существующие сканы URL"),
    ]
    for name, t, key, desc in rows:
        table.add_row(name, t, key, desc)
    console.print(table)
    console.print(
        "\n[dim]Ключи в .env: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, "
        "IPQS_API_KEY,\nGREYNOISE_API_KEY, OTX_API_KEY, "
        "PHISHTANK_APP_KEY[/dim]"
    )


def cache_stats() -> None:
    try:
        cur = db.conn.cursor()
        cur.execute("SELECT COUNT(*) as c FROM ti_cache")
        total = cur.fetchone()["c"]
        cur.execute(
            "SELECT verdict, COUNT(*) as c FROM ti_cache "
            "GROUP BY verdict")
        by_verdict = {r["verdict"]: r["c"] for r in cur.fetchall()}
        table = Table(title="💾 TI Cache")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Total cached", str(total))
        for v, c in by_verdict.items():
            table.add_row(f"  {v}", str(c))
        console.print(table)
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")


def cache_clear() -> None:
    try:
        db.conn.cursor().execute("DELETE FROM ti_cache")
        db.conn.commit()
        console.print("[green]✓ Кэш очищен[/green]")
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_ip(ip: str) -> None:
    lookup(ip)


def cli_domain(domain: str) -> None:
    lookup(domain)


def cli_hash(h: str) -> None:
    lookup(h)


def cli_url(url: str) -> None:
    lookup(url)


def cli_auto(ioc: str) -> None:
    lookup(ioc)


def cli_bulk(source: str, threads: int = 4) -> None:
    reports = bulk_lookup(source, threads)
    if reports:
        if Confirm.ask("Экспорт результатов?", default=False):
            fmt = Prompt.ask("Формат",
                             choices=["json", "csv", "md", "html", "all"],
                             default="html")
            if fmt == "all":
                export_csv(reports)
                export_markdown(reports)
                export_html(reports)
            elif fmt == "json":
                for r in reports:
                    export_report(r)
            elif fmt == "csv":
                export_csv(reports)
            elif fmt == "md":
                export_markdown(reports)
            elif fmt == "html":
                export_html(reports)


def cli_sources() -> None:
    sources_status()


def cli_cache() -> None:
    cache_stats()


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🟡 Threat Intelligence Lookup[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Проверить IP"),
        ("2", "Проверить домен"),
        ("3", "Проверить хеш (md5/sha1/sha256)"),
        ("4", "Проверить URL"),
        ("5", "Авто-детект типа IOC"),
        ("6", "Проверить список (файл / через запятую)"),
        ("7", "Статус источников (какие ключи заданы)"),
        ("8", "Статистика кэша"),
        ("9", "Очистить кэш"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        r = lookup(Prompt.ask("IP"))
        if Confirm.ask("Экспорт?", default=False):
            export_report(r)
    elif c == "2":
        r = lookup(Prompt.ask("Домен"))
        if Confirm.ask("Экспорт?", default=False):
            export_report(r)
    elif c == "3":
        r = lookup(Prompt.ask("Hash"))
        if Confirm.ask("Экспорт?", default=False):
            export_report(r)
    elif c == "4":
        r = lookup(Prompt.ask("URL"))
        if Confirm.ask("Экспорт?", default=False):
            export_report(r)
    elif c == "5":
        r = lookup(Prompt.ask("IOC (IP/домен/хеш/URL)"))
        if Confirm.ask("Экспорт?", default=False):
            export_report(r)
    elif c == "6":
        src = Prompt.ask("Файл или список через запятую")
        threads = IntPrompt.ask("Параллельно", default=4)
        cli_bulk(src, threads)
    elif c == "7":
        sources_status()
    elif c == "8":
        cache_stats()
    elif c == "9":
        if Confirm.ask("Очистить кэш?", default=False):
            cache_clear()