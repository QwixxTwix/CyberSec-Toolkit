"""
Threat Intelligence Lookup.
Author: idqwixxa

Мульти-API проверка IOC:
    - IP        → Shodan IDB, GreyNoise, AbuseIPDB, VirusTotal, OTX, IPQS
    - Domain    → VirusTotal, OTX, URLhaus, ThreatFox
    - Hash      → VirusTotal, MalwareBazaar, ThreatFox, OTX
    - URL       → VirusTotal, URLhaus, PhishTank

Ключи (опционально, в .env):
    VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, IPQS_API_KEY,
    GREYNOISE_API_KEY, OTX_API_KEY, URLSCAN_API_KEY, PHISHTANK_APP_KEY

Свободные источники (без ключа):
    Shodan InternetDB, URLhaus, MalwareBazaar, ThreatFox,
    GreyNoise Community, AlienVault OTX (limited)

Возможности:
    - Авто-детект типа IOC (IP / domain / hash / URL)
    - Проверка по всем доступным источникам параллельно
    - Единый verdict (clean / suspicious / malicious / unknown)
    - Экспорт JSON / CSV
    - Проверка списка IOC из файла
"""
import csv
import ipaddress
import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 15

# ===========================================================================
# Авто-детект типа IOC
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
    # IP (v4/v6)
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
    else:
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
    r.summary = f"{name or '?'} | noise={noise} riot={riot} last={last_seen[:10]}"
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
        headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
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
            {"cat": rep.get("categories"), "date": rep.get("reportedAt"),
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
        f"ASN={attrs.get('asn', '?')} owner={attrs.get('as_owner', '?')[:30]} "
        f"country={attrs.get('country', '?')}"
    )
    r.details = {
        "reputation": attrs.get("reputation"),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "network": attrs.get("network"),
        "stats": stats,
        "detected_by": list((attrs.get("last_analysis_results") or {}).keys())[:10],
    }
    return r


def src_otx_ip(ip: str) -> SourceResult:
    """AlienVault OTX (free, no key needed for basic)."""
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
        f"https://ipqualityscore.com/api/json/ip/{config.IPQS_API_KEY}/{ip}",
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
                f" | {data.get('ISP', '?')[:30]}"
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


IP_SOURCES = [
    src_shodan_idb,
    src_greynoise,
    src_abuseipdb,
    src_virustotal_ip,
    src_otx_ip,
    src_ipqs,
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
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
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
    names = [p.get("name", "")[:40] for p in (pulses.get("pulses") or [])[:3]]
    r.summary = " | ".join(names) if names else "no pulses"
    r.details = {
        "pulse_count": count,
        "pulses": [
            {"name": p.get("name"), "tags": p.get("tags", [])[:5]}
            for p in (pulses.get("pulses") or [])[:10]
        ],
        "whois": data.get("whois", "")[:300],
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


DOMAIN_SOURCES = [
    src_virustotal_domain,
    src_otx_domain,
    src_urlhaus_domain,
    src_threatfox_domain,
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
        f"type={attrs.get('type_description', '?')[:30]} "
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
        f"{e.get('file_type_mime', '?')[:30]} | "
        f"{e.get('signature') or '—'} | "
        f"first={e.get('first_seen', '?')[:10]}"
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
    # Определяем тип
    if RE_MD5.match(h):
        path = f"file/{h}"
    elif RE_SHA1.match(h):
        path = f"file/{h}"
    elif RE_SHA256.match(h):
        path = f"file/{h}"
    else:
        r.error = "unknown hash"
        return r
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/{path}/general",
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
    names = [p.get("name", "")[:40] for p in (pulses.get("pulses") or [])[:3]]
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
    import base64
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
        data={"url": url, "format": "json", "app_key": config.PHISHTANK_APP_KEY},
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


URL_SOURCES = [
    src_virustotal_url,
    src_urlhaus_url,
    src_phishtank,
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


def lookup(ioc: str, threads: int = 6) -> TIReport:
    """Проверить IOC по всем доступным источникам."""
    ioc = ioc.strip()
    ioc_type = detect_ioc_type(ioc)
    if ioc_type == "unknown":
        console.print(f"[red]Не удалось определить тип IOC: {ioc}[/red]")
        return TIReport(ioc=ioc, ioc_type="unknown",
                        ts=datetime.now().isoformat(timespec="seconds"))

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

    # Сортируем по алфавиту
    rep.sources.sort(key=lambda s: s.source)
    _print_report(rep)

    db.save_scan("threat_intel", f"{ioc_type}:{ioc}",
                 {"verdict": rep.verdict,
                  "malicious": rep.malicious_sources,
                  "suspicious": rep.suspicious_sources})
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
    # Summary
    v = rep.verdict
    sty = _verdict_style(v)
    console.print(
        f"[bold]IOC:[/bold] [cyan]{rep.ioc}[/cyan] "
        f"([magenta]{rep.ioc_type}[/magenta])"
    )
    console.print(
        f"[bold]Verdict:[/bold] [{sty}]{_verdict_icon(v)} "
        f"{v.upper()}[/{sty}]  "
        f"[dim]{len(rep.sources)} sources[/dim]"
    )

    # Table
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

    # Details (compact)
    for s in rep.sources:
        if s.ok and s.details:
            det_str = json.dumps(s.details, ensure_ascii=False,
                                 default=str)[:300]
            console.print(f"[dim]  {s.source}: {det_str}[/dim]")


# ===========================================================================
# Bulk
# ===========================================================================

def bulk_lookup(source: str, threads: int = 4) -> list[TIReport]:
    """
    Проверить список IOC из файла или строки через запятую.
    """
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
    # Ограничиваем параллельность чтобы не спалить rate-limits
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

    # Итоговая таблица
    t = Table(title=f"Bulk результат ({len(reports)})")
    t.add_column("IOC", style="cyan", max_width=45)
    t.add_column("Тип", style="magenta", width=8)
    t.add_column("Verdict", width=14)
    t.add_column("Malicious", style="red")
    t.add_column("Suspicious", style="yellow")
    for r in sorted(reports, key=lambda x: x.ioc):
        sty = _verdict_style(r.verdict)
        t.add_row(
            r.ioc[:45],
            r.ioc_type,
            f"[{sty}]{_verdict_icon(r.verdict)} {r.verdict}[/{sty}]",
            ", ".join(r.malicious_sources) or "—",
            ", ".join(r.suspicious_sources) or "—",
        )
    console.print(t)

    # Экспорт JSON
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = REPORT_DIR / f"ti_bulk_{ts}.json"
    try:
        data = [asdict(r) for r in reports]
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False,
                                  default=str), encoding="utf-8")
        console.print(f"[green]✓ JSON: {out}[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Не сохранил JSON: {exc}[/yellow]")
    return reports


def export_report(rep: TIReport, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", rep.ioc)[:40]
        path = str(REPORT_DIR / f"ti_{rep.ioc_type}_{safe}_{ts}.json")
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


def export_csv(reports: list[TIReport], path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(REPORT_DIR / f"ti_{ts}.csv")
    cols = ["ioc", "ioc_type", "verdict", "malicious", "suspicious", "clean"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in reports:
                w.writerow([
                    r.ioc, r.ioc_type, r.verdict,
                    ";".join(r.malicious_sources),
                    ";".join(r.suspicious_sources),
                    ";".join(r.clean_sources),
                ])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
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
         "Классификация: malicious/noise/benign (rate-limited)"),
        ("AbuseIPDB", "IP", "[green]да[/green]" if config.ABUSEIPDB_API_KEY
         else "[red]да[/red]",
         "Жалобы на IP, abuse confidence score"),
        ("VirusTotal", "IP/dom/hash/URL",
         "[green]да[/green]" if config.VIRUSTOTAL_API_KEY
         else "[red]да[/red]",
         "Мультискан 70+ антивирусов"),
        ("AlienVault OTX", "IP/dom/hash", "[yellow]опц.[/yellow]",
         "Pulses с IOC и malware-кампании"),
        ("IPQualityScore", "IP", "[green]да[/green]"
         if config.IPQS_API_KEY else "[red]да[/red]",
         "Fraud score, VPN/Proxy/Tor, recent abuse"),
        ("URLhaus", "Domain/URL", "[green]нет[/green]",
         "URL'ы с malware, malware distribution"),
        ("MalwareBazaar", "Hash", "[green]нет[/green]",
         "Образцы malware по хешу"),
        ("ThreatFox", "Domain/Hash/URL", "[green]нет[/green]",
         "Активные IOC с контекстом кампаний"),
        ("PhishTank", "URL", "[green]да[/green]"
         if config.PHISHTANK_APP_KEY else "[red]да[/red]",
         "Verified phishing URLs"),
    ]
    for name, t, key, desc in rows:
        table.add_row(name, t, key, desc)
    console.print(table)
    console.print(
        "\n[dim]Ключи добавляются в .env: VIRUSTOTAL_API_KEY, "
        "ABUSEIPDB_API_KEY, IPQS_API_KEY,\nGREYNOISE_API_KEY, "
        "OTX_API_KEY, PHISHTANK_APP_KEY[/dim]"
    )


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
    bulk_lookup(source, threads)


def cli_sources() -> None:
    sources_status()


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
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        lookup(Prompt.ask("IP"))
    elif c == "2":
        lookup(Prompt.ask("Домен"))
    elif c == "3":
        lookup(Prompt.ask("Hash"))
    elif c == "4":
        lookup(Prompt.ask("URL"))
    elif c == "5":
        lookup(Prompt.ask("IOC (IP/домен/хеш/URL)"))
    elif c == "6":
        src = Prompt.ask("Файл или список через запятую")
        threads = int(Prompt.ask("Параллельно", default="4"))
        bulk_lookup(src, threads)
    elif c == "7":
        sources_status()