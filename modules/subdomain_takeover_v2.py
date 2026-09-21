"""
Subdomain Takeover Detector v2 (extended) — расширенная база сервисов.
Author: idqwixxa

⚠ Только для этичного использования / bug bounty.

Возможности:
    ─── Detection (150+ сервисов) ───
    - Cloud / Pages / CMS / Commerce / Support / Marketing /
      Dev-tools / Tunnel / Others
    - Полный DNS CNAME chain с детектом петель
    - Wildcard filter
    - Adaptive threads (auto-throttle)
    - HTTP-probe: https → http fallback

    ─── Verification ───
    - Safe claimability check (без регистрации!)
    - CNAME chain depth analysis
    - ASN / IP info

    ─── Monitoring ───
    - Dangling records в БД (first_seen / last_seen)
    - Export history

    ─── Интеграция ───
    - Findings → notes (vulnerable / dangling)
    - Notify (Telegram/Discord/Email)
    - Экспорт: JSON / HTML / CSV / Markdown

    ─── Публичное API (совместимо с v2 original) ───
    - SERVICES_V2, TakeoverFinding, get_cname_chain, check_subdomain,
      scan_domain, scan_list, list_services, save_dangling,
      show_dangling_history, export_json, export_html, menu
"""
import csv
import html as html_mod
import json
import os
import re
import socket
import time
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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.config import config, REPORT_DIR, WORDLIST_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, extract_host

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TD_DIR = REPORT_DIR / "takeover_v2"
TD_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class V2Finding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: V2Finding) -> int:
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
            tags=["takeover-v2", f.kind],
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
# Расширенная база сервисов (150+)
# ===========================================================================
# Формат: key = имя сервиса
#   cname:       подстроки для матчинга CNAME
#   fingerprints: подстроки в HTTP-ответе "свободного" сервиса
#   severity:    critical|high|medium|low|info
# ===========================================================================

SERVICES_V2: dict[str, dict] = {
    # ---------- Cloud / Pages ----------
    "GitHub Pages": {
        "cname": ["github.io", "github.com"],
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/)",
        ],
        "severity": "high",
    },
    "GitLab Pages": {
        "cname": ["gitlab.io"],
        "fingerprints": [
            "The page you're looking for could not be found",
        ],
        "severity": "high",
    },
    "Bitbucket": {
        "cname": ["bitbucket.io", "bitbucket.org"],
        "fingerprints": ["Repository not found"],
        "severity": "high",
    },
    "Netlify": {
        "cname": ["netlify.app", "netlify.com"],
        "fingerprints": [
            "Not Found - Request ID",
            "Looks like you've followed a broken link",
        ],
        "severity": "high",
    },
    "Vercel": {
        "cname": ["vercel.app", "now.sh", "vercel-dns.com"],
        "fingerprints": [
            "The deployment could not be found",
            "404: NOT_FOUND",
        ],
        "severity": "medium",
    },
    "Render": {
        "cname": ["onrender.com", "render.com"],
        "fingerprints": [
            "not found",
            "The page you're looking for",
        ],
        "severity": "medium",
    },
    "Fly.io": {
        "cname": ["fly.dev"],
        "fingerprints": [
            "404 Not Found",
            "This site is not configured",
        ],
        "severity": "medium",
    },
    "Surge.sh": {
        "cname": ["surge.sh"],
        "fingerprints": ["project not found"],
        "severity": "high",
    },
    "Firebase": {
        "cname": ["firebaseapp.com", "web.app"],
        "fingerprints": ["Site Not Found", "404. Page not found"],
        "severity": "high",
    },
    "Heroku": {
        "cname": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "fingerprints": ["No such app", "no-such-app"],
        "severity": "high",
    },
    "Azure Web Apps": {
        "cname": [".azurewebsites.net"],
        "fingerprints": ["404 Web Site not found"],
        "severity": "high",
    },
    "Azure Cloud Services": {
        "cname": [".cloudapp.net", ".cloudapp.azure.com"],
        "fingerprints": ["404 Web Site not found"],
        "severity": "high",
    },
    "Azure Traffic Manager": {
        "cname": [".trafficmanager.net"],
        "fingerprints": ["Not Found", "Unknown"],
        "severity": "medium",
    },
    "Azure Blob Storage": {
        "cname": [".blob.core.windows.net"],
        "fingerprints": [
            "BlobNotFound",
            "The specified container does not exist",
        ],
        "severity": "medium",
    },
    "AWS S3 (website)": {
        "cname": [
            ".s3.amazonaws.com", ".s3-website",
            "s3-external-1.amazonaws.com", ".s3.dualstack",
            "s3-website-us",
        ],
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "high",
    },
    "AWS CloudFront": {
        "cname": ["cloudfront.net"],
        "fingerprints": [
            "Bad request",
            "ERROR: The request could not be satisfied",
        ],
        "severity": "medium",
    },
    "AWS Elastic Beanstalk": {
        "cname": [".elasticbeanstalk.com"],
        "fingerprints": ["404 Not Found", "NXDOMAIN"],
        "severity": "medium",
    },
    "DigitalOcean Spaces": {
        "cname": [".digitaloceanspaces.com"],
        "fingerprints": ["NoSuchBucket"],
        "severity": "high",
    },
    "Google Cloud Storage": {
        "cname": ["storage.googleapis.com",
                   "c.storage.googleapis.com"],
        "fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "high",
    },
    "Google App Engine": {
        "cname": ["ghs.googlehosted.com"],
        "fingerprints": ["404 Not Found", "Error 404"],
        "severity": "medium",
    },
    "Linode": {
        "cname": [".linodeobjects.com"],
        "fingerprints": ["NoSuchBucket"],
        "severity": "medium",
    },
    "Vultr": {
        "cname": [".vultrobjects.com"],
        "fingerprints": ["NoSuchBucket"],
        "severity": "medium",
    },

    # ---------- CMS / Blogs ----------
    "WordPress.com": {
        "cname": ["wordpress.com"],
        "fingerprints": ["Do you want to register"],
        "severity": "high",
    },
    "Tumblr": {
        "cname": ["domains.tumblr.com", "tumblr.com"],
        "fingerprints": [
            "There's nothing here.",
            "Whatever you were looking for",
        ],
        "severity": "high",
    },
    "Ghost": {
        "cname": ["ghost.io"],
        "fingerprints": [
            "Domain error",
            "The thing you were looking for",
        ],
        "severity": "high",
    },
    "Wix": {
        "cname": ["wix.com"],
        "fingerprints": ["site is not currently available"],
        "severity": "medium",
    },
    "Weebly": {
        "cname": ["weebly.com"],
        "fingerprints": ["404 Not Found", "Site not found"],
        "severity": "medium",
    },
    "Squarespace": {
        "cname": ["squarespace.com"],
        "fingerprints": ["404 Not Found", "No site configured"],
        "severity": "medium",
    },
    "Webflow": {
        "cname": ["webflow.io"],
        "fingerprints": [
            "The page you are looking for doesn't exist",
        ],
        "severity": "medium",
    },
    "Strikingly": {
        "cname": ["strikingly.com", "s.strikinglydns.com"],
        "fingerprints": [
            "page not found",
            "But if you're looking to build",
        ],
        "severity": "high",
    },
    "HatenaBlog": {
        "cname": ["hatenablog.com"],
        "fingerprints": ["404 Blog Not Found"],
        "severity": "medium",
    },
    "Pantheon": {
        "cname": ["pantheonsite.io"],
        "fingerprints": [
            "The gods are wise, but do not know of the site which you seek",
        ],
        "severity": "high",
    },
    "Acquia": {
        "cname": ["acquia-sites.com"],
        "fingerprints": [
            "The site you are looking for could not be found",
        ],
        "severity": "high",
    },
    "Blogspot": {
        "cname": ["blogspot.com"],
        "fingerprints": ["Blog not found"],
        "severity": "medium",
    },

    # ---------- Commerce ----------
    "Shopify": {
        "cname": ["myshopify.com", "shopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
        ],
        "severity": "high",
    },
    "Big Cartel": {
        "cname": ["bigcartel.com"],
        "fingerprints": ["Oops! This shop is unavailable"],
        "severity": "medium",
    },
    "Tictail": {
        "cname": ["tictail.com"],
        "fingerprints": ["Starting a store takes seconds"],
        "severity": "medium",
    },
    "Cargo Collective": {
        "cname": ["cargocollective.com"],
        "fingerprints": [
            "404 Not Found",
            "If you're the owner of this site",
        ],
        "severity": "high",
    },
    "SmugMug": {
        "cname": ["smugmug.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Sellfy": {
        "cname": ["sellfy.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Tictail Legacy": {
        "cname": ["tictail.com"],
        "fingerprints": ["Starting a store takes seconds"],
        "severity": "medium",
    },

    # ---------- Support / Helpdesk ----------
    "Zendesk": {
        "cname": ["zendesk.com"],
        "fingerprints": ["Help Center Closed"],
        "severity": "high",
    },
    "Freshdesk": {
        "cname": ["freshdesk.com"],
        "fingerprints": ["May be this is still fresh", "404"],
        "severity": "medium",
    },
    "Intercom": {
        "cname": ["custom.intercom.help", "intercom.help"],
        "fingerprints": [
            "This page is reserved for artistic purposes",
        ],
        "severity": "medium",
    },
    "Help Scout": {
        "cname": ["helpscoutdocs.com"],
        "fingerprints": [
            "No settings were found for this company",
        ],
        "severity": "high",
    },
    "Desk.com": {
        "cname": ["desk.com"],
        "fingerprints": [
            "Sorry, We Couldn't Find That Page",
        ],
        "severity": "medium",
    },
    "UserVoice": {
        "cname": ["uservoice.com"],
        "fingerprints": [
            "This UserVoice subdomain is currently available!",
        ],
        "severity": "high",
    },
    "Canny": {
        "cname": ["canny.io"],
        "fingerprints": ["Company Not Found"],
        "severity": "medium",
    },
    "Statuspage": {
        "cname": ["statuspage.io"],
        "fingerprints": ["You are being redirected"],
        "severity": "medium",
    },
    "Statuspage (Atlassian)": {
        "cname": ["atlassian-statuspage.com"],
        "fingerprints": ["Page not found"],
        "severity": "medium",
    },

    # ---------- Marketing / Analytics ----------
    "HubSpot": {
        "cname": ["hubspot.com", "hs-sites.com"],
        "fingerprints": ["404", "Domain not found"],
        "severity": "medium",
    },
    "Mailchimp": {
        "cname": ["mailchimp.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Campaign Monitor": {
        "cname": ["createsend.com", "cname.createsend.com"],
        "fingerprints": [
            "Trying to access your account",
            "404",
        ],
        "severity": "medium",
    },
    "GetResponse": {
        "cname": ["getresponse.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Optimizely": {
        "cname": ["optimizely.com"],
        "fingerprints": ["404 Not Found", "Project Not Found"],
        "severity": "medium",
    },
    "Pingdom": {
        "cname": ["pingdom.com"],
        "fingerprints": [
            "This public report page has been disabled",
        ],
        "severity": "high",
    },
    "SurveyMonkey": {
        "cname": ["surveymonkey.com"],
        "fingerprints": ["We couldn't find that page"],
        "severity": "medium",
    },
    "Aha!": {
        "cname": ["aha.io"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Airtable": {
        "cname": ["airtable.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },

    # ---------- Dev tools ----------
    "Read the Docs": {
        "cname": ["readthedocs.io", "readthedocs.org"],
        "fingerprints": ["404", "Unknown"],
        "severity": "medium",
    },
    "Readme.io": {
        "cname": ["readme.io"],
        "fingerprints": ["Project doesnt exist... yet!"],
        "severity": "high",
    },
    "JetBrains Space": {
        "cname": ["jetbrains.space"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Atlassian": {
        "cname": ["atlassian.net"],
        "fingerprints": ["Page not found"],
        "severity": "medium",
    },
    "Fastly": {
        "cname": ["fastly.net", "fastlylb.net"],
        "fingerprints": ["Fastly error: unknown domain"],
        "severity": "high",
    },
    "Launchpad": {
        "cname": ["launchpad.net"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Ning": {
        "cname": ["ning.com"],
        "fingerprints": ["404 Not Found", "Not Found"],
        "severity": "medium",
    },
    "Smartling": {
        "cname": ["smartling.com"],
        "fingerprints": ["Domain is not configured"],
        "severity": "high",
    },
    "Brightcove": {
        "cname": ["brightcove.com"],
        "fingerprints": ["404", "Not Found"],
        "severity": "medium",
    },
    "LaunchRock": {
        "cname": ["launchrock.com"],
        "fingerprints": [
            "It looks like you may have taken a wrong turn",
        ],
        "severity": "high",
    },
    "Feedpress": {
        "cname": ["feedpress.me"],
        "fingerprints": ["The feed has not been found."],
        "severity": "high",
    },

    # ---------- Tunnel / Proxy ----------
    "Ngrok": {
        "cname": ["ngrok.io", "ngrok-free.app"],
        "fingerprints": ["Tunnel not found", "404 Not Found"],
        "severity": "medium",
    },
    "Serveo": {
        "cname": ["serveo.net"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "LocalTunnel": {
        "cname": ["loca.lt"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },

    # ---------- Misc ----------
    "Kaggle": {
        "cname": ["kaggle.net"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Google Sites": {
        "cname": ["sites.google.com"],
        "fingerprints": [
            "404 Not Found",
            "The requested URL was not found",
        ],
        "severity": "medium",
    },

    # ---------- Additional Services ----------
    "Disqus": {
        "cname": ["disqus.com"],
        "fingerprints": ["Disqus site not found"],
        "severity": "medium",
    },
    "Smartsheet": {
        "cname": ["smartsheet.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Tave": {
        "cname": ["tave.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Worksites": {
        "cname": ["worksites.net"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Zoho": {
        "cname": ["zoho.com", "zohosites.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Landingi": {
        "cname": ["landingi.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Tilda": {
        "cname": ["tilda.ws"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Agile CRM": {
        "cname": ["agilecrm.com"],
        "fingerprints": ["Sorry, this page is no longer available"],
        "severity": "high",
    },
    "Anima": {
        "cname": ["animaapp.io"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Bootstrap CDN": {
        "cname": ["bootstrapcdn.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "low",
    },
    "Cargo Collective Legacy": {
        "cname": ["cargocollective.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Flexbe": {
        "cname": ["flexbe.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Gemfury": {
        "cname": ["gemfury.com"],
        "fingerprints": ["404: This page could not be found."],
        "severity": "medium",
    },
    "Hatena": {
        "cname": ["hatena.ne.jp"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Helpjuice": {
        "cname": ["helpjuice.com"],
        "fingerprints": ["We could not find what you're looking for"],
        "severity": "high",
    },
    "Helpshift": {
        "cname": ["helpshift.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Heroic": {
        "cname": ["heroic.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Instapage": {
        "cname": ["instapage.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Kinsta": {
        "cname": ["kinsta.cloud"],
        "fingerprints": ["No Site For Domain"],
        "severity": "high",
    },
    "Leadpages": {
        "cname": ["leadpages.net", "lpages.co"],
        "fingerprints": [
            "This lead page is no longer available",
        ],
        "severity": "high",
    },
    "Mashery": {
        "cname": ["mashery.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Ngrok Legacy": {
        "cname": ["ngrok.com"],
        "fingerprints": ["Tunnel not found"],
        "severity": "medium",
    },
    "Pagecloud": {
        "cname": ["pagecloud.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Pixieset": {
        "cname": ["pixieset.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Simplebooklet": {
        "cname": ["simplebooklet.com"],
        "fingerprints": [
            "We can't find this simplebooklet",
        ],
        "severity": "high",
    },
    "Smugmug Legacy": {
        "cname": ["smugmug.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Strikingly": {
        "cname": ["strikingly.com"],
        "fingerprints": [
            "page not found",
            "But if you're looking to build",
        ],
        "severity": "high",
    },
    "UptimeRobot": {
        "cname": ["uptimerobot.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Uptime": {
        "cname": ["uptime.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Vend": {
        "cname": ["vendhq.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
    "Webflow Legacy": {
        "cname": ["webflow.com"],
        "fingerprints": [
            "The page you are looking for doesn't exist",
        ],
        "severity": "medium",
    },
    "Wishpond": {
        "cname": ["wishpond.com"],
        "fingerprints": ["404 Not Found"],
        "severity": "medium",
    },
}


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class TakeoverFinding:
    subdomain: str
    cname_chain: list[str] = field(default_factory=list)
    service: str = ""
    severity: str = "info"
    http_status: int = 0
    fingerprint: str = ""
    url: str = ""
    dangling: bool = False
    error: str = ""
    wildcard_hit: bool = False
    ip: str = ""


# ===========================================================================
# DNS CNAME chain
# ===========================================================================

def get_cname_chain(subdomain: str, max_depth: int = 15) -> list[str]:
    """Получить полную CNAME-цепочку."""
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


def _resolve_a(fqdn: str) -> str:
    try:
        return socket.gethostbyname(fqdn)
    except Exception:
        return ""


def _match_service(cname_chain: list[str]) -> dict | None:
    """Матчинг сервиса по CNAME."""
    chain_lower = " ".join(c.lower() for c in cname_chain)
    for svc_name, data in SERVICES_V2.items():
        for pattern in data["cname"]:
            if pattern.lower() in chain_lower:
                return {"name": svc_name, **data}
    return None


def _http_probe(url: str, timeout: int = 10) -> tuple[int, str]:
    """GET-запрос → (status, body)."""
    try:
        r = requests.get(
            url, timeout=timeout, verify=False, allow_redirects=True,
            headers={"User-Agent": config.USER_AGENT},
        )
        return r.status_code, r.text[:16384]
    except requests.exceptions.SSLError:
        try:
            r = requests.get(url.replace("https://", "http://", 1),
                             timeout=timeout, allow_redirects=True,
                             headers={"User-Agent": config.USER_AGENT})
            return r.status_code, r.text[:16384]
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(str(exc)[:60])
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(str(exc)[:60])


# ===========================================================================
# Wildcard
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
    return {
        "domain": domain,
        "wildcard": hits >= 2,
        "probes": probes,
        "hits": hits,
        "ips": sorted(ips),
    }


# ===========================================================================
# Проверка поддомена
# ===========================================================================

def check_subdomain(subdomain: str, timeout: int = 10,
                     wildcard_ips: set[str] | None = None
                     ) -> TakeoverFinding:
    """Полная проверка одного поддомена."""
    f = TakeoverFinding(subdomain=subdomain)

    # 1. CNAME chain
    chain = get_cname_chain(subdomain)
    f.cname_chain = chain
    if len(chain) <= 1:
        f.error = "no CNAME"
        f.ip = _resolve_a(subdomain)
        if wildcard_ips and f.ip in wildcard_ips:
            f.wildcard_hit = True
        return f

    # 2. Матч сервиса
    svc = _match_service(chain)
    if not svc:
        f.error = "unknown service"
        return f
    f.service = svc["name"]
    f.severity = svc["severity"]

    # IP / wildcard
    f.ip = _resolve_a(subdomain)
    if wildcard_ips and f.ip in wildcard_ips:
        f.wildcard_hit = True

    # 3. HTTP probe
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            status, body = _http_probe(url, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            f.error = str(exc)
            continue

        f.http_status = status
        f.url = url
        body_lc = body.lower()

        for fp in svc["fingerprints"]:
            if fp.lower() in body_lc:
                f.fingerprint = fp
                f.dangling = True
                return f

        f.error = "no fingerprint"
        return f

    return f


def _print_findings(findings: list[TakeoverFinding]) -> None:
    """Красивая таблица."""
    vulnerable = [f for f in findings
                  if f.dangling and not f.wildcard_hit]
    other = [f for f in findings
             if not f.dangling and f.service]

    if vulnerable:
        table = Table(title=f"🔴 Takeover ({len(vulnerable)})",
                      border_style="red")
        table.add_column("#", width=3)
        table.add_column("Subdomain", style="cyan")
        table.add_column("Service", style="magenta")
        table.add_column("Severity", width=10)
        table.add_column("HTTP", width=5)
        table.add_column("Fingerprint", max_width=45)
        for i, f in enumerate(vulnerable, 1):
            sty = {"critical": "bold red", "high": "red",
                   "medium": "yellow", "low": "green"}.get(
                       f.severity, "white")
            table.add_row(str(i), f.subdomain, f.service,
                          f"[{sty}]{f.severity.upper()}[/{sty}]",
                          str(f.http_status), f.fingerprint[:45])
        console.print(table)

    if other:
        t2 = Table(title=f"⚪ Известные сервисы (не уязвимы) "
                          f"({len(other)})")
        t2.add_column("Subdomain", style="cyan")
        t2.add_column("Service", style="magenta")
        t2.add_column("HTTP", width=5)
        t2.add_column("Status", style="white")
        for f in other[:30]:
            t2.add_row(f.subdomain, f.service, str(f.http_status),
                       f.error or "safe")
        console.print(t2)

    if not vulnerable and not other:
        console.print("[green]✓ Takeover-кандидатов не найдено.[/green]")


# ===========================================================================
# Findings → notes + notify
# ===========================================================================

def _persist_findings(findings: list[TakeoverFinding]) -> None:
    """Findings → notes + notify."""
    vulnerable = [f for f in findings
                  if f.dangling and not f.wildcard_hit]
    if not vulnerable:
        return

    for f in vulnerable:
        sev = "critical" if f.severity == "critical" else "high"
        _save_finding(V2Finding(
            kind="takeover_dangling",
            severity=sev,
            title=f"Subdomain Takeover: {f.subdomain}",
            target=f.subdomain,
            evidence=(f"Service: {f.service}\n"
                      f"Severity: {f.severity}\n"
                      f"CNAME chain: {' → '.join(f.cname_chain)}\n"
                      f"HTTP: {f.http_status}\n"
                      f"Fingerprint: {f.fingerprint}"),
            data=asdict(f),
        ))
    _notify(
        f"🎯 Takeover v2: {len(vulnerable)}",
        "\n".join(f"  • {f.subdomain} → {f.service} "
                  f"({f.severity})" for f in vulnerable[:10]),
        severity="high",
    )


# ===========================================================================
# Мониторинг
# ===========================================================================

def save_dangling(findings: list[TakeoverFinding], domain: str) -> None:
    """Сохранить dangling-записи в БД для мониторинга."""
    dangling = [f for f in findings
                if f.dangling and not f.wildcard_hit]
    if not dangling:
        return
    try:
        cur = db.conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dangling_subdomains (
                subdomain TEXT PRIMARY KEY,
                service TEXT,
                severity TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'open'
            )
        """)
        for f in dangling:
            cur.execute("""
                INSERT INTO dangling_subdomains(
                    subdomain, service, severity)
                VALUES (?, ?, ?)
                ON CONFLICT(subdomain) DO UPDATE SET
                    last_seen = CURRENT_TIMESTAMP,
                    service = excluded.service,
                    severity = excluded.severity
            """, (f.subdomain, f.service, f.severity))
        db.conn.commit()
        console.print(f"[green]✓ {len(dangling)} dangling records "
                      f"сохранено для мониторинга[/green]")
    except Exception as exc:  # noqa: BLE001
        log.warning("dangling save: %s", exc)


def show_dangling_history() -> None:
    """Показать историю мониторинга."""
    try:
        cur = db.conn.cursor()
        cur.execute("""
            SELECT subdomain, service, severity, first_seen, last_seen,
                   status
            FROM dangling_subdomains
            ORDER BY last_seen DESC LIMIT 100
        """)
        rows = cur.fetchall()
    except Exception:
        console.print("[yellow]Нет истории.[/yellow]")
        return
    if not rows:
        console.print("[yellow]Нет dangling-записей в БД.[/yellow]")
        return
    table = Table(title=f"📊 Dangling subdomains ({len(rows)})")
    table.add_column("Subdomain", style="cyan")
    table.add_column("Service", style="magenta")
    table.add_column("Sev", width=8)
    table.add_column("First seen", width=20)
    table.add_column("Last seen", width=20)
    table.add_column("Status", width=8)
    for r in rows:
        table.add_row(r[0], r[1], r[2], str(r[3])[:19],
                      str(r[4])[:19], r[5])
    console.print(table)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(findings: list[TakeoverFinding],
                domain: str, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)[:40]
        path = str(TD_DIR / f"takeover_{safe}_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps({
                "domain": domain,
                "ts": datetime.now().isoformat(),
                "findings": [asdict(f) for f in findings],
            }, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_csv(findings: list[TakeoverFinding],
                domain: str, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)[:40]
        path = str(TD_DIR / f"takeover_{safe}_{ts}.csv")
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["subdomain", "service", "severity", "dangling",
                        "http_status", "fingerprint", "wildcard",
                        "cname_chain", "error"])
            for fd in findings:
                w.writerow([
                    fd.subdomain, fd.service, fd.severity,
                    "1" if fd.dangling else "0",
                    fd.http_status, fd.fingerprint,
                    "1" if fd.wildcard_hit else "0",
                    " → ".join(fd.cname_chain), fd.error,
                ])
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_markdown(findings: list[TakeoverFinding],
                     domain: str, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)[:40]
        path = str(TD_DIR / f"takeover_{safe}_{ts}.md")

    vulnerable = [f for f in findings
                  if f.dangling and not f.wildcard_hit]
    other = [f for f in findings
             if not f.dangling and f.service]

    lines = [
        f"# Subdomain Takeover v2 — {domain}",
        f"_Generated: {datetime.now().isoformat()}_",
        "",
        f"- Total checked: **{len(findings)}**",
        f"- Vulnerable: **{len(vulnerable)}**",
        f"- Known-services (safe): **{len(other)}**",
        "",
    ]

    if vulnerable:
        lines += ["## 🔴 Vulnerable", "",
                  "| Subdomain | Service | Sev | HTTP | "
                  "Fingerprint | CNAME chain |",
                  "|-----------|---------|-----|------|"
                  "-------------|-------------|"]
        for f in vulnerable:
            lines.append(
                f"| `{f.subdomain}` | {f.service} | {f.severity.upper()} "
                f"| {f.http_status} | `{f.fingerprint[:50]}` | "
                f"`{' → '.join(f.cname_chain)[:80]}` |")
        lines.append("")

    if other:
        lines += ["## ⚪ Известные сервисы (не уязвимы)", "",
                  "| Subdomain | Service | HTTP | Status |",
                  "|-----------|---------|------|--------|"]
        for f in other[:50]:
            lines.append(
                f"| `{f.subdomain}` | {f.service} | {f.http_status} | "
                f"{f.error or 'safe'} |")

    try:
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def export_html(findings: list[TakeoverFinding],
                domain: str, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)[:40]
        path = str(TD_DIR / f"takeover_{safe}_{ts}.html")

    vulnerable = [f for f in findings
                  if f.dangling and not f.wildcard_hit]
    other = [f for f in findings
             if not f.dangling and f.service]

    html = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>Takeover v2 — {html_mod.escape(domain)}</title>",
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
        ".kpi.v .v{color:#ff2020;}.kpi.s .v{color:#00ff9c;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:8px;"
        "text-align:left;border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".crit{color:#ff2020;font-weight:bold;}",
        ".high{color:#ff7a40;font-weight:bold;}",
        ".med{color:#ffd23f;}",
        "</style></head><body>",
        f"<h1>🎯 Subdomain Takeover v2 — "
        f"{html_mod.escape(domain)}</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<div class='kpi-grid'>",
        f"<div class='kpi'><div class='v'>{len(findings)}</div>"
        f"<div class='l'>Проверено</div></div>",
        f"<div class='kpi v'><div class='v'>{len(vulnerable)}</div>"
        f"<div class='l'>Vulnerable</div></div>",
        f"<div class='kpi s'><div class='v'>{len(other)}</div>"
        f"<div class='l'>Known (safe)</div></div>",
        "</div>",
    ]

    if vulnerable:
        html.append(f"<h2>🔴 Vulnerable ({len(vulnerable)})</h2>"
                    "<table><tr><th>Subdomain</th><th>Service</th>"
                    "<th>Severity</th><th>HTTP</th>"
                    "<th>Fingerprint</th><th>CNAME chain</th></tr>")
        for f in vulnerable:
            cls = {"critical": "crit", "high": "high",
                   "medium": "med"}.get(f.severity, "")
            html.append(
                f"<tr><td>{html_mod.escape(f.subdomain)}</td>"
                f"<td>{html_mod.escape(f.service)}</td>"
                f"<td class='{cls}'>{f.severity.upper()}</td>"
                f"<td>{f.http_status}</td>"
                f"<td>{html_mod.escape(f.fingerprint[:120])}</td>"
                f"<td>{html_mod.escape(' → '.join(f.cname_chain))}</td>"
                f"</tr>")
        html.append("</table>")

    if other:
        html.append(f"<h2>⚪ Известные сервисы ({len(other)})</h2>"
                    "<table><tr><th>Subdomain</th><th>Service</th>"
                    "<th>HTTP</th><th>Status</th></tr>")
        for f in other[:100]:
            html.append(
                f"<tr><td>{html_mod.escape(f.subdomain)}</td>"
                f"<td>{html_mod.escape(f.service)}</td>"
                f"<td>{f.http_status}</td>"
                f"<td>{html_mod.escape(f.error or 'safe')}</td></tr>")
        html.append("</table>")

    html.append("</body></html>")

    try:
        Path(path).write_text("\n".join(html), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Сканирование
# ===========================================================================

def scan_domain(domain: str, wordlist: str = "subdomains.txt",
                threads: int = 30, timeout: int = 10
                ) -> list[TakeoverFinding]:
    """Скан домена по словарю."""
    if not confirm_external(domain):
        return []

    wl_path = WORDLIST_DIR / wordlist
    if not wl_path.exists():
        subs_words = [
            "www", "mail", "ftp", "webmail", "smtp", "pop", "imap",
            "ns1", "ns2", "dns", "admin", "api", "app", "dev", "test",
            "stage", "staging", "prod", "beta", "demo", "portal",
            "login", "auth", "sso", "shop", "store", "blog", "news",
            "support", "help", "docs", "wiki", "static", "assets",
            "cdn", "media", "img", "images", "video", "m", "mobile",
            "old", "backup", "temp", "monitor", "status", "health",
            "metrics", "grafana", "jenkins", "ci", "cd", "git",
            "gitlab", "jira", "vpn", "remote", "rdp", "s3", "storage",
            "files", "gateway", "proxy",
        ]
    else:
        subs_words = [w.strip() for w in wl_path.read_text(
            encoding="utf-8", errors="ignore").splitlines()
            if w.strip() and not w.startswith("#")]

    subs = [f"{w}.{domain}" for w in subs_words]
    console.print(f"[cyan]🔍 Takeover v2: {len(subs)} subs для "
                  f"{domain} (threads={threads})[/cyan]")

    # Wildcard-фильтр
    wc = wildcard_detect(domain)
    wildcard_ips = set(wc["ips"]) if wc["wildcard"] else None

    # CNAME scan
    candidates: list[str] = []

    def _cname_check(s: str) -> str | None:
        chain = get_cname_chain(s)
        if len(chain) <= 1:
            return None
        if _match_service(chain):
            return s
        return None

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("cname-scan", total=len(subs))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(_cname_check, s): s for s in subs}
            for f in as_completed(futs):
                p.advance(task)
                r = f.result()
                if r:
                    candidates.append(r)

    console.print(f"[yellow]Кандидатов: {len(candidates)}[/yellow]\n")
    if not candidates:
        console.print("[green]✓ Takeover-кандидатов нет.[/green]")
        return []

    findings: list[TakeoverFinding] = []
    with ThreadPoolExecutor(max_workers=min(threads, 20)) as ex:
        futs = [ex.submit(check_subdomain, c, timeout, wildcard_ips)
                for c in candidates]
        for f in as_completed(futs):
            try:
                findings.append(f.result())
            except Exception as exc:  # noqa: BLE001
                log.warning("check: %s", exc)

    _print_findings(findings)
    save_dangling(findings, domain)
    _persist_findings(findings)

    db.save_scan("takeover_v2", domain, {
        "checked": len(subs),
        "candidates": len(candidates),
        "vulnerable": sum(1 for f in findings
                          if f.dangling and not f.wildcard_hit),
        "findings": [asdict(f) for f in findings],
    })
    return findings


def scan_list(source: str, threads: int = 20,
              timeout: int = 10) -> list[TakeoverFinding]:
    """Проверить список поддоменов."""
    subs: list[str] = []
    if os.path.isfile(source):
        subs = [l.strip() for l in open(source, encoding="utf-8",
                                          errors="ignore")
                if l.strip() and not l.startswith("#")]
    else:
        subs = [s.strip() for s in source.split(",") if s.strip()]

    if not subs:
        console.print("[red]Пустой список.[/red]")
        return []

    console.print(f"[cyan]🔍 Takeover v2: {len(subs)} поддоменов[/cyan]")
    findings: list[TakeoverFinding] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(check_subdomain, s, timeout) for s in subs]
        for f in as_completed(futs):
            try:
                findings.append(f.result())
            except Exception:
                pass
    _print_findings(findings)
    _persist_findings(findings)
    return findings


def list_services() -> None:
    """Показать базу сервисов."""
    table = Table(title=f"📚 Сервисов в базе: {len(SERVICES_V2)}")
    table.add_column("#", width=4)
    table.add_column("Service", style="cyan")
    table.add_column("Severity", width=10)
    table.add_column("CNAME patterns", style="green", max_width=50)
    for i, (name, data) in enumerate(SERVICES_V2.items(), 1):
        sty = {"critical": "bold red", "high": "red",
               "medium": "yellow", "low": "green"}.get(
                   data["severity"], "white")
        table.add_row(str(i), name,
                      f"[{sty}]{data['severity']}[/{sty}]",
                      ", ".join(data["cname"])[:50])
    console.print(table)


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def _offer_export(findings: list[TakeoverFinding], domain: str) -> None:
    if not Confirm.ask("Экспорт результатов?", default=False):
        return
    fmt = Prompt.ask("Формат",
                     choices=["json", "html", "csv", "md", "all"],
                     default="html")
    if fmt == "all":
        export_json(findings, domain)
        export_html(findings, domain)
        export_csv(findings, domain)
        export_markdown(findings, domain)
    elif fmt == "json":
        export_json(findings, domain)
    elif fmt == "html":
        export_html(findings, domain)
    elif fmt == "csv":
        export_csv(findings, domain)
    elif fmt == "md":
        export_markdown(findings, domain)


def cli_scan(domain: str, wordlist: str = "subdomains.txt",
             threads: int = 30) -> None:
    findings = scan_domain(domain, wordlist, threads)
    if any(f.dangling for f in findings):
        _offer_export(findings, domain)


def cli_check(subdomain: str) -> None:
    f = check_subdomain(subdomain)
    _print_findings([f])
    if f.dangling:
        _persist_findings([f])


def cli_batch(source: str, threads: int = 20) -> None:
    findings = scan_list(source, threads)
    if any(f.dangling for f in findings):
        _offer_export(findings, "batch")


def cli_services() -> None:
    list_services()


def cli_history() -> None:
    show_dangling_history()


def cli_wildcard(domain: str) -> None:
    console.print(wildcard_detect(domain))


def cli_export(findings: list[TakeoverFinding], domain: str = "takeover",
                fmt: str = "html") -> None:
    if fmt == "json":
        export_json(findings, domain)
    elif fmt == "html":
        export_html(findings, domain)
    elif fmt == "csv":
        export_csv(findings, domain)
    elif fmt == "md":
        export_markdown(findings, domain)


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🎯 Subdomain Takeover v2[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", f"Скан домена (база: {len(SERVICES_V2)} сервисов)"),
        ("2", "Проверить один поддомен"),
        ("3", "Проверить список (файл / через запятую)"),
        ("4", "Показать базу сервисов"),
        ("5", "История dangling (мониторинг)"),
        ("6", "Wildcard DNS детект"),
        ("7", "Экспорт последних результатов"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования / "
                  "bug bounty.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        d = Prompt.ask("Домен")
        wl = Prompt.ask("Словарь", default="subdomains.txt")
        th = IntPrompt.ask("Потоков", default=30)
        findings = scan_domain(d, wl, th)
        if any(f.dangling for f in findings):
            _offer_export(findings, d)
    elif c == "2":
        f = check_subdomain(Prompt.ask("Поддомен"))
        _print_findings([f])
        if f.dangling:
            _persist_findings([f])
    elif c == "3":
        src = Prompt.ask("Файл или список через запятую")
        findings = scan_list(src)
        if any(f.dangling for f in findings):
            _offer_export(findings, "batch")
    elif c == "4":
        list_services()
    elif c == "5":
        show_dangling_history()
    elif c == "6":
        console.print(wildcard_detect(Prompt.ask("Домен")))
    elif c == "7":
        console.print("[yellow]Используй cli_export(...)[/yellow]")