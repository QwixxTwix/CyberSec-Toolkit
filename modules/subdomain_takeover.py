"""
Subdomain Takeover Detector (extended).
Author: idqwixxa

⚠ Только для этичного использования и CTF / bug-bounty.

Возможности:
    ─── Detection ───
    - 60+ SaaS-сервисов с CNAME + HTTP fingerprints
    - Полный CNAME-чейн (с детектом петель)
    - Wildcard DNS-фильтр (отсеивает ложные срабатывания)
    - HTTP-probe с fallback https → http
    - Auto-throttle (adaptive threads)

    ─── Интеграция ───
    - Findings → notes (vulnerable / edge-case)
    - Notify (Telegram/Discord/Email) при critical
    - Экспорт: JSON / CSV / Markdown / HTML

    ─── Массовые проверки ───
    - scan_domain (wordlist brute + check)
    - scan_list (файл или список через запятую)
    - check_many (параллельная проверка)

    ─── Дополнительно ───
    - resolve CNAME chain depth
    - Auto-detect wildcard *.domain
    - Save results в БД
"""
import csv
import html as html_mod
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import dns.resolver
import requests
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.config import config, WORDLIST_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TK_DIR = REPORT_DIR / "takeover"
TK_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class TKFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: TKFinding) -> int:
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
            tags=["takeover", f.kind],
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
# База известных сервисов (расширено до 60+)
# ===========================================================================

SERVICES: dict[str, dict[str, Any]] = {
    # ---------- Cloud / Pages ----------
    "github.io": {
        "service": "GitHub Pages",
        "cname_patterns": ["github.io", "github.com"],
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/)",
        ],
        "status": "vulnerable",
    },
    "herokuapp": {
        "service": "Heroku",
        "cname_patterns": ["herokuapp.com", "herokussl.com",
                            "herokudns.com"],
        "fingerprints": ["No such app", "heroku | no such app",
                          "no-such-app"],
        "status": "vulnerable",
    },
    "s3": {
        "service": "AWS S3",
        "cname_patterns": [
            ".s3.amazonaws.com", ".s3-website",
            "s3-external-1.amazonaws.com", ".s3.dualstack",
            "s3-website",
        ],
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
            "Code: NoSuchBucket",
        ],
        "status": "vulnerable",
    },
    "cloudfront": {
        "service": "AWS CloudFront",
        "cname_patterns": ["cloudfront.net"],
        "fingerprints": [
            "Bad request",
            "ERROR: The request could not be satisfied",
            "CloudFront attempted to establish a connection",
        ],
        "status": "edge-case",
    },
    "elasticbeanstalk": {
        "service": "AWS Elastic Beanstalk",
        "cname_patterns": [".elasticbeanstalk.com"],
        "fingerprints": ["404 Not Found", "NXDOMAIN"],
        "status": "edge-case",
    },
    "azure": {
        "service": "Azure (Web Apps / Cloud Services)",
        "cname_patterns": [
            ".azurewebsites.net", ".cloudapp.net",
            ".cloudapp.azure.com", ".trafficmanager.net",
            ".blob.core.windows.net", ".azure-api.net",
            ".azurefd.net",
        ],
        "fingerprints": [
            "404 Web Site not found",
            "Error 404 - Web app not found",
            "The resource you are looking for has been removed",
        ],
        "status": "vulnerable",
    },
    "gcs": {
        "service": "Google Cloud Storage",
        "cname_patterns": ["storage.googleapis.com",
                            "c.storage.googleapis.com"],
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "status": "vulnerable",
    },
    "ghs-googlehosted": {
        "service": "Google App Engine",
        "cname_patterns": ["ghs.googlehosted.com"],
        "fingerprints": ["404 Not Found", "Error 404"],
        "status": "edge-case",
    },
    "firebaseapp": {
        "service": "Firebase",
        "cname_patterns": ["firebaseapp.com", "web.app"],
        "fingerprints": ["Site Not Found", "404. Page not found"],
        "status": "vulnerable",
    },
    "netlify": {
        "service": "Netlify",
        "cname_patterns": ["netlify.app", "netlify.com"],
        "fingerprints": [
            "Not Found - Request ID",
            "Looks like you've followed a broken link",
        ],
        "status": "vulnerable",
    },
    "vercel": {
        "service": "Vercel",
        "cname_patterns": ["vercel.app", "vercel.com", "now.sh",
                            "vercel-dns.com"],
        "fingerprints": [
            "The deployment you are looking for",
            "404: NOT_FOUND",
        ],
        "status": "edge-case",
    },
    "surge": {
        "service": "Surge.sh",
        "cname_patterns": ["surge.sh"],
        "fingerprints": [
            "project not found",
            "404 Not Found: project not found",
        ],
        "status": "vulnerable",
    },
    "render": {
        "service": "Render",
        "cname_patterns": ["onrender.com", "render.com"],
        "fingerprints": [
            "not found",
            "The page you're looking for doesn't exist",
        ],
        "status": "edge-case",
    },
    "fly": {
        "service": "Fly.io",
        "cname_patterns": ["fly.dev"],
        "fingerprints": [
            "404 Not Found",
            "This site is not configured",
        ],
        "status": "edge-case",
    },
    "fastly": {
        "service": "Fastly",
        "cname_patterns": ["fastly.net", "fastlylb.net"],
        "fingerprints": [
            "Fastly error: unknown domain",
            "Please check that this domain has been added to a service",
        ],
        "status": "vulnerable",
    },
    "digitalocean": {
        "service": "DigitalOcean Spaces",
        "cname_patterns": [".digitaloceanspaces.com"],
        "fingerprints": ["NoSuchBucket"],
        "status": "vulnerable",
    },

    # ---------- CMS / Blogs ----------
    "shopify": {
        "service": "Shopify",
        "cname_patterns": ["myshopify.com", "shopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        "status": "vulnerable",
    },
    "tumblr": {
        "service": "Tumblr",
        "cname_patterns": ["domains.tumblr.com", "tumblr.com"],
        "fingerprints": [
            "There's nothing here.",
            "Whatever you were looking for doesn't currently exist",
        ],
        "status": "vulnerable",
    },
    "wordpress": {
        "service": "WordPress.com",
        "cname_patterns": ["wordpress.com"],
        "fingerprints": [
            "Do you want to register",
            "WordPress.com",
        ],
        "status": "vulnerable",
    },
    "wix": {
        "service": "Wix",
        "cname_patterns": ["wix.com"],
        "fingerprints": [
            "site is not currently available",
        ],
        "status": "vulnerable",
    },
    "weebly": {
        "service": "Weebly",
        "cname_patterns": ["weebly.com"],
        "fingerprints": ["404 Not Found", "Site not found"],
        "status": "vulnerable",
    },
    "squarespace": {
        "service": "Squarespace",
        "cname_patterns": ["squarespace.com"],
        "fingerprints": ["404 Not Found", "No site configured"],
        "status": "edge-case",
    },
    "webflow": {
        "service": "Webflow",
        "cname_patterns": ["webflow.io"],
        "fingerprints": [
            "The page you are looking for doesn't exist",
        ],
        "status": "vulnerable",
    },
    "ghost": {
        "service": "Ghost",
        "cname_patterns": ["ghost.io"],
        "fingerprints": [
            "Domain error",
            "The thing you were looking for is no longer here",
        ],
        "status": "vulnerable",
    },
    "strikingly": {
        "service": "Strikingly",
        "cname_patterns": ["strikingly.com", "s.strikinglydns.com"],
        "fingerprints": [
            "page not found",
            "But if you're looking to build your own",
        ],
        "status": "vulnerable",
    },
    "hatenablog": {
        "service": "HatenaBlog",
        "cname_patterns": ["hatenablog.com"],
        "fingerprints": ["404 Blog Not Found"],
        "status": "vulnerable",
    },
    "tictail": {
        "service": "Tictail",
        "cname_patterns": ["tictail.com"],
        "fingerprints": [
            "to target URL: https://tictail.com",
            "Starting a store takes seconds",
        ],
        "status": "vulnerable",
    },
    "smugmug": {
        "service": "SmugMug",
        "cname_patterns": ["smugmug.com"],
        "fingerprints": [
            "404 Not Found",
            "The page you're looking for doesn't exist",
        ],
        "status": "vulnerable",
    },
    "cargocollective": {
        "service": "Cargo Collective",
        "cname_patterns": ["cargocollective.com"],
        "fingerprints": [
            "If you're the owner of this website",
            "404 Not Found",
        ],
        "status": "vulnerable",
    },
    "udemy": {
        "service": "Udemy",
        "cname_patterns": ["udemy.com"],
        "fingerprints": [
            "This site is not currently available",
        ],
        "status": "vulnerable",
    },

    # ---------- Support / Helpdesk ----------
    "zendesk": {
        "service": "Zendesk",
        "cname_patterns": ["zendesk.com"],
        "fingerprints": ["Help Center Closed", "Zendesk Support"],
        "status": "vulnerable",
    },
    "freshdesk": {
        "service": "Freshdesk",
        "cname_patterns": ["freshdesk.com"],
        "fingerprints": ["May be this is still fresh", "404"],
        "status": "edge-case",
    },
    "helpscout": {
        "service": "Help Scout",
        "cname_patterns": ["helpscoutdocs.com"],
        "fingerprints": [
            "No settings were found for this company",
        ],
        "status": "vulnerable",
    },
    "uservoice": {
        "service": "UserVoice",
        "cname_patterns": ["uservoice.com"],
        "fingerprints": [
            "This UserVoice subdomain is currently available!",
        ],
        "status": "vulnerable",
    },
    "statuspage": {
        "service": "Atlassian Statuspage",
        "cname_patterns": ["statuspage.io", "atlassian-statuspage.com"],
        "fingerprints": [
            "You are being redirected",
            "This page is used to test",
            "Page not found",
        ],
        "status": "edge-case",
    },
    "canny": {
        "service": "Canny",
        "cname_patterns": ["canny.io"],
        "fingerprints": ["Company Not Found"],
        "status": "vulnerable",
    },
    "intercom": {
        "service": "Intercom",
        "cname_patterns": ["custom.intercom.help", "intercom.help"],
        "fingerprints": [
            "This page is reserved for artistic purposes",
        ],
        "status": "vulnerable",
    },

    # ---------- Dev tools ----------
    "bitbucket": {
        "service": "Bitbucket",
        "cname_patterns": ["bitbucket.io", "bitbucket.org"],
        "fingerprints": [
            "Repository not found",
            "The page you're looking for doesn't exist",
        ],
        "status": "vulnerable",
    },
    "gitlab": {
        "service": "GitLab Pages",
        "cname_patterns": ["gitlab.io"],
        "fingerprints": [
            "The page you're looking for could not be found",
        ],
        "status": "vulnerable",
    },
    "readme": {
        "service": "Readme.io",
        "cname_patterns": ["readme.io"],
        "fingerprints": ["Project doesnt exist... yet!"],
        "status": "vulnerable",
    },
    "readthedocs": {
        "service": "Read the Docs",
        "cname_patterns": ["readthedocs.io", "readthedocs.org"],
        "fingerprints": ["404", "Unknown"],
        "status": "edge-case",
    },
    "pantheon": {
        "service": "Pantheon",
        "cname_patterns": ["pantheonsite.io"],
        "fingerprints": [
            "The gods are wise, but do not know of the site which you seek",
            "404: This page could not be found",
        ],
        "status": "vulnerable",
    },
    "acquia": {
        "service": "Acquia",
        "cname_patterns": ["acquia-sites.com"],
        "fingerprints": [
            "The site you are looking for could not be found",
        ],
        "status": "vulnerable",
    },
    "smartling": {
        "service": "Smartling",
        "cname_patterns": ["smartling.com"],
        "fingerprints": ["Domain is not configured"],
        "status": "vulnerable",
    },
    "launchrock": {
        "service": "LaunchRock",
        "cname_patterns": ["launchrock.com"],
        "fingerprints": [
            "It looks like you may have taken a wrong turn",
        ],
        "status": "vulnerable",
    },
    "pingdom": {
        "service": "Pingdom",
        "cname_patterns": ["pingdom.com"],
        "fingerprints": [
            "This public report page has been disabled",
        ],
        "status": "vulnerable",
    },
    "feedpress": {
        "service": "Feedpress",
        "cname_patterns": ["feedpress.me"],
        "fingerprints": ["The feed has not been found."],
        "status": "vulnerable",
    },
    "freshdesk2": {
        "service": "Freshdesk (alt)",
        "cname_patterns": ["freshservice.com"],
        "fingerprints": ["May be this is still fresh"],
        "status": "edge-case",
    },
    "aha": {
        "service": "Aha!",
        "cname_patterns": ["aha.io"],
        "fingerprints": ["404 Not Found"],
        "status": "edge-case",
    },
    "airtable": {
        "service": "Airtable",
        "cname_patterns": ["airtable.com"],
        "fingerprints": ["404 Not Found"],
        "status": "edge-case",
    },
    "surveymonkey": {
        "service": "SurveyMonkey",
        "cname_patterns": ["surveymonkey.com"],
        "fingerprints": ["We couldn't find that page"],
        "status": "edge-case",
    },
    "hubspot": {
        "service": "HubSpot",
        "cname_patterns": ["hubspot.com", "hs-sites.com"],
        "fingerprints": ["404", "Domain not found"],
        "status": "edge-case",
    },
    "mailchimp": {
        "service": "Mailchimp",
        "cname_patterns": ["mailchimp.com"],
        "fingerprints": ["404 Not Found"],
        "status": "edge-case",
    },
    "campaignmonitor": {
        "service": "Campaign Monitor",
        "cname_patterns": ["createsend.com", "cname.createsend.com"],
        "fingerprints": ["Trying to access your account", "404"],
        "status": "edge-case",
    },
    "optimizely": {
        "service": "Optimizely",
        "cname_patterns": ["optimizely.com"],
        "fingerprints": ["404 Not Found", "Project Not Found"],
        "status": "edge-case",
    },
    "atlassian": {
        "service": "Atlassian Cloud",
        "cname_patterns": ["atlassian.net"],
        "fingerprints": ["Page not found"],
        "status": "edge-case",
    },
    "jetbrains": {
        "service": "JetBrains Space",
        "cname_patterns": ["jetbrains.space"],
        "fingerprints": ["404 Not Found"],
        "status": "edge-case",
    },

    # ---------- Misc ----------
    "launchpad": {
        "service": "Launchpad",
        "cname_patterns": ["launchpad.net"],
        "fingerprints": ["404 Not Found"],
        "status": "edge-case",
    },
    "ning": {
        "service": "Ning",
        "cname_patterns": ["ning.com"],
        "fingerprints": ["404 Not Found", "Not Found"],
        "status": "edge-case",
    },
    "brightcove": {
        "service": "Brightcove",
        "cname_patterns": ["brightcove.com"],
        "fingerprints": ["404", "Not Found"],
        "status": "edge-case",
    },
    "google-sites": {
        "service": "Google Sites",
        "cname_patterns": ["sites.google.com"],
        "fingerprints": ["404 Not Found",
                          "The requested URL was not found"],
        "status": "edge-case",
    },
    "blogspot": {
        "service": "Google Blogger",
        "cname_patterns": ["blogspot.com"],
        "fingerprints": ["Blog not found"],
        "status": "edge-case",
    },
    "ngrok": {
        "service": "Ngrok",
        "cname_patterns": ["ngrok.io", "ngrok-free.app"],
        "fingerprints": ["Tunnel not found", "404 Not Found"],
        "status": "edge-case",
    },
    "serveo": {
        "service": "Serveo",
        "cname_patterns": ["serveo.net"],
        "fingerprints": ["404 Not Found"],
        "status": "edge-case",
    },
    "localtunnel": {
        "service": "LocalTunnel",
        "cname_patterns": ["loca.lt"],
        "fingerprints": ["404 Not Found"],
        "status": "edge-case",
    },
    "kaggle": {
        "service": "Kaggle",
        "cname_patterns": ["kaggle.net"],
        "fingerprints": ["404 Not Found"],
        "status": "edge-case",
    },
}


# ===========================================================================
# Модель результата
# ===========================================================================

@dataclass
class TakeoverResult:
    subdomain: str
    cname: str = ""
    service: str = ""
    status: str = "safe"        # vulnerable | edge-case | safe | error
    http_status: int = 0
    fingerprint: str = ""
    error: str = ""
    ip: str = ""
    cname_chain: list[str] = field(default_factory=list)
    wildcard_hit: bool = False


# ===========================================================================
# Резолв
# ===========================================================================

def _resolve_cname(subdomain: str) -> str:
    """Резолв CNAME-цепочки; возвращает финальный target."""
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME", lifetime=5)
        target = str(answers[0].target).rstrip(".")
        for _ in range(10):
            try:
                next_ans = dns.resolver.resolve(target, "CNAME",
                                                  lifetime=5)
                next_target = str(next_ans[0].target).rstrip(".")
                if next_target == target:
                    break
                target = next_target
            except Exception:
                break
        return target
    except Exception:
        return ""


def cname_chain_full(subdomain: str,
                     max_depth: int = 15) -> list[str]:
    """Полная CNAME-цепочка с детектом петель."""
    chain: list[str] = [subdomain]
    current = subdomain
    visited: set[str] = {subdomain}
    for _ in range(max_depth):
        try:
            answers = dns.resolver.resolve(current, "CNAME", lifetime=5)
            target = str(answers[0].target).rstrip(".")
            if target in visited:
                chain.append(f"{target} (loop)")
                break
            chain.append(target)
            visited.add(target)
            current = target
        except dns.resolver.NoAnswer:
            break
        except Exception:
            break
    return chain


def _resolve_a(subdomain: str) -> str:
    """A-резолв."""
    try:
        return socket.gethostbyname(subdomain)
    except Exception:
        return ""


# ===========================================================================
# Матчинг сервиса
# ===========================================================================

def _match_service(cname: str) -> dict | None:
    """Найти сервис по подстроке CNAME."""
    lc = cname.lower()
    for svc_key, data in SERVICES.items():
        for pattern in data["cname_patterns"]:
            if pattern.lower() in lc:
                return {"key": svc_key, **data}
    return None


def _http_probe(url: str, timeout: int = 10) -> tuple[int, str]:
    """GET-запрос, вернуть (status, body[:8192])."""
    try:
        r = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": config.USER_AGENT},
        )
        return r.status_code, r.text[:8192]
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url.replace("https://", "http://", 1),
                             timeout=timeout, allow_redirects=True,
                             headers={"User-Agent": config.USER_AGENT})
            return r.status_code, r.text[:8192]
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"http fallback failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(str(exc)[:80])


# ===========================================================================
# Wildcard detection
# ===========================================================================

def wildcard_detect(domain: str) -> dict:
    """Детект wildcard *.domain."""
    import random
    import string as _string
    probes = []
    for _ in range(3):
        rand = "".join(random.choices(
            _string.ascii_lowercase + _string.digits, k=14))
        probes.append(f"{rand}.{domain}")
    hits = 0
    ips: set[str] = set()
    for p in probes:
        ip = _resolve_a(p)
        if ip:
            hits += 1
            ips.add(ip)
    result = {
        "domain": domain,
        "wildcard": hits >= 2,
        "probes": probes,
        "hits": hits,
        "ips": sorted(ips),
    }
    if result["wildcard"]:
        console.print(f"[yellow]⚠ Wildcard DNS на {domain}: "
                      f"{sorted(ips)}[/yellow]")
    return result


# ===========================================================================
# Проверка
# ===========================================================================

def check_subdomain(subdomain: str, timeout: int = 10,
                     verbose: bool = False,
                     wildcard_ips: set[str] | None = None
                     ) -> TakeoverResult:
    """
    Полная проверка одного поддомена:
        1) резолв CNAME-цепочки
        2) матчинг сервиса
        3) HTTP-probe
        4) сверка fingerprint
    """
    result = TakeoverResult(subdomain=subdomain)

    # CNAME chain
    chain = cname_chain_full(subdomain)
    result.cname_chain = chain

    if len(chain) <= 1:
        result.error = "no CNAME"
        # всё же попробуем A-резолв для wildcard-фильтра
        result.ip = _resolve_a(subdomain)
        if wildcard_ips and result.ip in wildcard_ips:
            result.wildcard_hit = True
        return result

    result.cname = chain[-1]

    # Матч сервиса
    svc = _match_service(result.cname)
    if not svc:
        result.service = "(unknown)"
        result.error = "not a known service"
        return result
    result.service = svc["service"]

    # A-резолв + wildcard-фильтр
    result.ip = _resolve_a(subdomain)
    if wildcard_ips and result.ip in wildcard_ips:
        result.wildcard_hit = True

    # HTTP-probe
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            status, body = _http_probe(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            if scheme == "http":
                result.error = str(exc)[:100]
                return result
            continue

        result.http_status = status
        body_lc = body.lower()
        for fp in svc["fingerprints"]:
            if fp.lower() in body_lc:
                result.fingerprint = fp
                result.status = svc["status"]
                return result

        result.status = "safe"
        return result

    result.status = "safe"
    return result


# ===========================================================================
# Пакетная проверка
# ===========================================================================

def check_many(subdomains: list[str], threads: int = 20,
                timeout: int = 10,
                wildcard_ips: set[str] | None = None,
                save_findings: bool = True) -> list[TakeoverResult]:
    """Параллельная проверка списка поддоменов."""
    results: list[TakeoverResult] = []
    total = len(subdomains)
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(check_subdomain, sd, timeout, False, wildcard_ips): sd
            for sd in subdomains
        }
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as p:
            task = p.add_task(f"Проверяю {total} поддоменов…",
                              total=total)
            for f in as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as exc:  # noqa: BLE001
                    sd = futures[f]
                    results.append(TakeoverResult(
                        subdomain=sd, error=str(exc)[:80]))
                p.advance(task)

    if save_findings:
        _persist_findings(results)
    return results


def _persist_findings(results: list[TakeoverResult]) -> None:
    """Findings → notes + notify."""
    vulnerable = [r for r in results
                  if r.status == "vulnerable" and not r.wildcard_hit]
    edge = [r for r in results
            if r.status == "edge-case" and not r.wildcard_hit]

    for r in vulnerable:
        _save_finding(TKFinding(
            kind="subdomain_takeover",
            severity="high",
            title=f"Takeover возможен: {r.subdomain}",
            target=r.subdomain,
            evidence=(f"CNAME: {r.cname}\n"
                      f"Service: {r.service}\n"
                      f"HTTP: {r.http_status}\n"
                      f"Fingerprint: {r.fingerprint}"),
            data=asdict(r),
        ))
    if vulnerable:
        _notify(
            f"🎯 Takeover: {len(vulnerable)}",
            "\n".join(f"  • {r.subdomain} → {r.service}"
                      for r in vulnerable[:10]),
            severity="high",
        )


def _print_results(results: list[TakeoverResult],
                    title: str = "Takeover") -> None:
    """Красивая таблица результатов."""
    vulnerable = [r for r in results if r.status == "vulnerable"]
    edge = [r for r in results if r.status == "edge-case"]
    safe = [r for r in results if r.status == "safe"]

    if vulnerable:
        table = Table(title=f"🔴 {title} — УЯЗВИМЫ ({len(vulnerable)})",
                      border_style="red")
        table.add_column("Subdomain", style="cyan")
        table.add_column("CNAME", style="yellow", max_width=40)
        table.add_column("Сервис", style="magenta")
        table.add_column("HTTP", width=5)
        table.add_column("Wild", width=5)
        table.add_column("Fingerprint", max_width=45)
        for r in vulnerable:
            table.add_row(r.subdomain, r.cname, r.service,
                          str(r.http_status),
                          "🌐" if r.wildcard_hit else "—",
                          r.fingerprint[:45])
        console.print(table)

    if edge:
        table = Table(title=f"🟡 {title} — возможно ({len(edge)})",
                      border_style="yellow")
        table.add_column("Subdomain", style="cyan")
        table.add_column("CNAME", style="yellow", max_width=40)
        table.add_column("Сервис", style="magenta")
        table.add_column("HTTP", width=5)
        for r in edge:
            table.add_row(r.subdomain, r.cname, r.service,
                          str(r.http_status))
        console.print(table)

    if safe:
        console.print(f"\n[green]✓ Безопасных: {len(safe)}[/green]")
        if len(safe) <= 20:
            for r in safe:
                console.print(f"  [dim]{r.subdomain} → "
                              f"{r.service or r.cname or r.error}[/dim]")

    if not (vulnerable or edge or safe):
        console.print("[yellow]Ничего не проверено.[/yellow]")


# ===========================================================================
# Сканирование домена
# ===========================================================================

def scan_domain(domain: str, wordlist: str | None = None,
                threads: int = 30, timeout: int = 10) -> list[TakeoverResult]:
    """
    Брут поддоменов по словарю + проверка каждого на takeover.
    """
    if not confirm_external(domain):
        return []

    wl_name = wordlist or "subdomains.txt"
    wl_path = WORDLIST_DIR / wl_name
    if not wl_path.exists():
        console.print(f"[red]Словарь {wl_path} не найден.[/red]")
        return []

    words = [w.strip() for w in wl_path.read_text(
        encoding="utf-8", errors="ignore").splitlines() if w.strip()]
    subs = [f"{w}.{domain}" for w in words]

    console.print(f"[cyan]🔍 Проверяю {len(subs)} поддоменов {domain} "
                  f"на takeover…[/cyan]")

    # Wildcard-фильтр
    wc = wildcard_detect(domain)
    wildcard_ips = set(wc["ips"]) if wc["wildcard"] else None

    # Быстрый CNAME-скан
    def _cname_only(sd: str) -> str | None:
        c = _resolve_cname(sd)
        if not c:
            return None
        if _match_service(c):
            return sd
        return None

    candidates: list[str] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_cname_only, sd): sd for sd in subs}
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as p:
            task = p.add_task("Резолв CNAME…", total=len(subs))
            for f in as_completed(futures):
                r = f.result()
                if r:
                    candidates.append(r)
                p.advance(task)

    console.print(f"[cyan]Кандидатов (CNAME → сервис): "
                  f"{len(candidates)}[/cyan]")
    if not candidates:
        console.print("[green]Подозрительных поддоменов нет.[/green]")
        db.save_scan("takeover", domain,
                     {"scanned": len(subs), "candidates": 0})
        return []

    results = check_many(candidates, threads=threads, timeout=timeout,
                          wildcard_ips=wildcard_ips)
    _print_results(results, title=f"Takeover {domain}")

    db.save_scan("takeover", domain, {
        "scanned": len(subs),
        "candidates": len(candidates),
        "vulnerable": [r.subdomain for r in results
                       if r.status == "vulnerable"
                       and not r.wildcard_hit],
        "edge": [r.subdomain for r in results
                 if r.status == "edge-case" and not r.wildcard_hit],
    })
    return results


def scan_list(path_or_list: str, threads: int = 20,
                timeout: int = 10) -> list[TakeoverResult]:
    """
    Проверка списка поддоменов из файла или строки через запятую.
    """
    import os
    subs: list[str] = []
    if os.path.isfile(path_or_list):
        try:
            subs = [l.strip() for l in open(path_or_list,
                                              encoding="utf-8",
                                              errors="ignore")
                    if l.strip() and not l.startswith("#")]
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Не могу прочитать файл: {exc}[/red]")
            return []
    else:
        subs = [s.strip() for s in path_or_list.split(",") if s.strip()]

    if not subs:
        console.print("[red]Пустой список.[/red]")
        return []

    console.print(f"[cyan]🔍 Проверяю {len(subs)} поддоменов…[/cyan]")
    results = check_many(subs, threads=threads, timeout=timeout)
    _print_results(results, title="Takeover batch")

    db.save_scan("takeover_list", f"{len(subs)} subs", {
        "vulnerable": [r.subdomain for r in results
                       if r.status == "vulnerable"],
    })
    return results


def list_services() -> None:
    """Показать базу поддерживаемых сервисов."""
    table = Table(title=f"📚 Сервисы ({len(SERVICES)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Сервис", style="cyan")
    table.add_column("CNAME patterns", style="green", max_width=50)
    table.add_column("Статус", style="magenta", width=12)
    for i, (key, data) in enumerate(SERVICES.items(), 1):
        sty = {"vulnerable": "red", "edge-case": "yellow",
               "safe": "green"}.get(data["status"], "white")
        table.add_row(
            str(i),
            data["service"],
            ", ".join(data["cname_patterns"])[:50],
            f"[{sty}]{data['status']}[/{sty}]",
        )
    console.print(table)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(results: list[TakeoverResult],
                 target: str = "takeover",
                 out_path: str | None = None) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
    if not out_path:
        out_path = str(TK_DIR / f"takeover_{safe}_{ts}.json")
    try:
        Path(out_path).write_text(json.dumps({
            "target": target,
            "ts": datetime.now().isoformat(),
            "results": [asdict(r) for r in results],
        }, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(results: list[TakeoverResult],
                target: str = "takeover",
                out_path: str | None = None) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
    if not out_path:
        out_path = str(TK_DIR / f"takeover_{safe}_{ts}.csv")
    try:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["subdomain", "cname", "service", "status",
                        "http_status", "fingerprint", "wildcard",
                        "error"])
            for r in results:
                w.writerow([
                    r.subdomain, r.cname, r.service, r.status,
                    r.http_status, r.fingerprint,
                    "1" if r.wildcard_hit else "0",
                    r.error,
                ])
        console.print(f"[green]✓ CSV: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_markdown(results: list[TakeoverResult],
                     target: str = "takeover",
                     out_path: str | None = None) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
    if not out_path:
        out_path = str(TK_DIR / f"takeover_{safe}_{ts}.md")

    vulnerable = [r for r in results if r.status == "vulnerable"]
    edge = [r for r in results if r.status == "edge-case"]

    lines = [
        f"# Subdomain Takeover — {target}",
        f"_Generated: {datetime.now().isoformat()}_",
        "",
        f"- Всего проверено: **{len(results)}**",
        f"- Vulnerable: **{len(vulnerable)}**",
        f"- Edge-case: **{len(edge)}**",
        "",
    ]

    if vulnerable:
        lines += ["## 🔴 Уязвимы", "",
                  "| Subdomain | CNAME | Service | HTTP | Fingerprint |",
                  "|-----------|-------|---------|------|-------------|"]
        for r in vulnerable:
            lines.append(
                f"| `{r.subdomain}` | `{r.cname[:50]}` | "
                f"{r.service} | {r.http_status} | "
                f"`{r.fingerprint[:50]}` |")
        lines.append("")

    if edge:
        lines += ["## 🟡 Возможно уязвимы", "",
                  "| Subdomain | CNAME | Service | HTTP |",
                  "|-----------|-------|---------|------|"]
        for r in edge:
            lines.append(
                f"| `{r.subdomain}` | `{r.cname[:50]}` | "
                f"{r.service} | {r.http_status} |")
        lines.append("")

    try:
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]MD: {exc}[/red]")
        return None


def export_html(results: list[TakeoverResult],
                 target: str = "takeover",
                 out_path: str | None = None) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)[:40]
    if not out_path:
        out_path = str(TK_DIR / f"takeover_{safe}_{ts}.html")

    vulnerable = [r for r in results
                  if r.status == "vulnerable" and not r.wildcard_hit]
    edge = [r for r in results
            if r.status == "edge-case" and not r.wildcard_hit]

    parts = [
        "<!DOCTYPE html><html lang='ru'><head>"
        "<meta charset='utf-8'>",
        f"<title>Takeover — {html_mod.escape(target)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;"
        "font-family:monospace;padding:24px;max-width:1300px;"
        "margin:0 auto;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        ".kpi-grid{display:grid;"
        "grid-template-columns:repeat(auto-fit,minmax(160px,1fr));"
        "gap:14px;margin:20px 0;}",
        ".kpi{background:#111;border:1px solid #222;"
        "border-radius:8px;padding:16px;text-align:center;}",
        ".kpi .v{font-size:26px;font-weight:bold;}",
        ".kpi .l{font-size:11px;color:#888;"
        "text-transform:uppercase;margin-top:4px;}",
        ".kpi.vuln .v{color:#ff2020;}.kpi.edge .v{color:#ffd23f;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:6px;"
        "text-align:left;border:1px solid #222;}",
        "td{padding:5px 8px;border:1px solid #222;"
        "word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".vuln{color:#ff2020;font-weight:bold;}",
        "</style></head><body>",
        f"<h1>🎯 Subdomain Takeover — {html_mod.escape(target)}</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<div class='kpi-grid'>",
        f"<div class='kpi'><div class='v'>{len(results)}</div>"
        f"<div class='l'>Проверено</div></div>",
        f"<div class='kpi vuln'><div class='v'>{len(vulnerable)}</div>"
        f"<div class='l'>Vulnerable</div></div>",
        f"<div class='kpi edge'><div class='v'>{len(edge)}</div>"
        f"<div class='l'>Edge-case</div></div>",
        "</div>",
    ]

    if vulnerable:
        parts.append(f"<h2>🔴 Уязвимы ({len(vulnerable)})</h2>"
                     "<table><tr><th>Subdomain</th><th>CNAME</th>"
                     "<th>Service</th><th>HTTP</th>"
                     "<th>Fingerprint</th><th>CNAME chain</th></tr>")
        for r in vulnerable:
            parts.append(
                f"<tr><td class='vuln'>{html_mod.escape(r.subdomain)}</td>"
                f"<td>{html_mod.escape(r.cname)}</td>"
                f"<td>{html_mod.escape(r.service)}</td>"
                f"<td>{r.http_status}</td>"
                f"<td>{html_mod.escape(r.fingerprint[:80])}</td>"
                f"<td>{html_mod.escape(' → '.join(r.cname_chain))}</td></tr>")
        parts.append("</table>")

    if edge:
        parts.append(f"<h2>🟡 Edge-case ({len(edge)})</h2>"
                     "<table><tr><th>Subdomain</th><th>CNAME</th>"
                     "<th>Service</th><th>HTTP</th></tr>")
        for r in edge:
            parts.append(
                f"<tr><td>{html_mod.escape(r.subdomain)}</td>"
                f"<td>{html_mod.escape(r.cname)}</td>"
                f"<td>{html_mod.escape(r.service)}</td>"
                f"<td>{r.http_status}</td></tr>")
        parts.append("</table>")

    parts.append("</body></html>")

    try:
        Path(out_path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🎯 Subdomain Takeover Detector[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", f"Скан домена (база: {len(SERVICES)} сервисов)"),
        ("2", "Проверить один поддомен"),
        ("3", "Проверить список (файл / через запятую)"),
        ("4", "Показать базу сервисов"),
        ("5", "Wildcard DNS детект"),
        ("6", "Экспорт последних результатов"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        domain = Prompt.ask("Домен")
        wl = Prompt.ask("Словарь", default="subdomains.txt")
        threads = IntPrompt.ask("Потоков", default=30)
        results = scan_domain(domain, wordlist=wl, threads=threads)
        if results:
            _offer_export(results, domain)
    elif c == "2":
        sub = Prompt.ask("Поддомен (например old.example.com)")
        if not confirm_external(sub):
            return
        r = check_subdomain(sub, verbose=True)
        _print_results([r], title=sub)
        if r.status in ("vulnerable", "edge-case"):
            _persist_findings([r])
    elif c == "3":
        src = Prompt.ask("Файл или список через запятую")
        threads = IntPrompt.ask("Потоков", default=20)
        results = scan_list(src, threads=threads)
        if results:
            _offer_export(results, "batch")
    elif c == "4":
        list_services()
    elif c == "5":
        wc = wildcard_detect(Prompt.ask("Домен"))
        console.print(wc)
    elif c == "6":
        console.print("[yellow]Используй cli_export_* функции.[/yellow]")


def _offer_export(results: list[TakeoverResult], target: str) -> None:
    if not Confirm.ask("Экспорт результатов?", default=False):
        return
    fmt = Prompt.ask("Формат",
                     choices=["json", "csv", "md", "html", "all"],
                     default="html")
    if fmt == "all":
        export_json(results, target)
        export_csv(results, target)
        export_markdown(results, target)
        export_html(results, target)
    elif fmt == "json":
        export_json(results, target)
    elif fmt == "csv":
        export_csv(results, target)
    elif fmt == "md":
        export_markdown(results, target)
    elif fmt == "html":
        export_html(results, target)


# ===========================================================================
# CLI-функции (без интерактива)
# ===========================================================================

def cli_scan(domain: str, wordlist: str = "subdomains.txt",
             threads: int = 30) -> None:
    results = scan_domain(domain, wordlist=wordlist, threads=threads)
    if results:
        _offer_export(results, domain)


def cli_check(subdomain: str) -> None:
    r = check_subdomain(subdomain)
    _print_results([r], title=subdomain)
    if r.status in ("vulnerable", "edge-case"):
        _persist_findings([r])


def cli_batch(source: str, threads: int = 20) -> None:
    results = scan_list(source, threads=threads)
    if results:
        _offer_export(results, "batch")


def cli_services() -> None:
    list_services()


def cli_wildcard(domain: str) -> None:
    console.print(wildcard_detect(domain))


def cli_export(results: list[TakeoverResult], target: str = "takeover",
                fmt: str = "html") -> None:
    if fmt == "json":
        export_json(results, target)
    elif fmt == "csv":
        export_csv(results, target)
    elif fmt == "md":
        export_markdown(results, target)
    elif fmt == "html":
        export_html(results, target)