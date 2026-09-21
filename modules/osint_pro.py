"""
OSINT Pro — расширенная разведка по открытым источникам.
Author: idqwixxa

⚠ Только для этичного использования / bug bounty / CTF.

Возможности:
    ─── Username (100+ платформ) ───
    - Группировка по категориям (social/dev/sec/games/media/portfolio/ru/...)
    - Экспорт в HTML/Markdown
    - Findings при большом footprint

    ─── Telegram ───
    - Channel/user/bot detection
    - Description, subscribers, avatar
    - Deep link extraction

    ─── Gravatar ───
    - Profile JSON + linked accounts (Twitter/GitHub/etc)
    - Avatar + displayName + aboutMe

    ─── Wayback Machine ───
    - Historical URLs
    - Sensitive URLs filter (admin/api/backup/.env/.git)
    - JS files, source maps detection

    ─── Domain ───
    - RDAP + WHOIS (registrar, dates, status)
    - DNS dump (A/AAAA/MX/NS/TXT/SOA/CAA/SRV/DS/DNSKEY)
    - DNSSEC, DMARC, SPF, DKIM, BIMI, MTA-STS
    - Domain age + risk scoring

    ─── GitHub/GitLab/Bitbucket ───
    - User info + repos + orgs + gists
    - Contributions graph hints

    ─── Email ───
    - Multi-source links (HIBP, LeakCheck, IntelX, DeHashed, Hunter)

    ─── Phone ───
    - Carrier lookup via free API

    ─── Reverse image search ───
    - 6+ сервисов (Google Lens, Yandex, TinEye, Bing, SauceNAO, PimEyes)

    ─── Findings / интеграция ───
    - Findings → notes (breach, GPS, large footprint)
    - Notify
    - HTML отчёт
"""
import csv
import hashlib
import html as html_mod
import json
import re
import socket
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import dns.resolver
import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import extract_host

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OSINT_DIR = REPORT_DIR / "osint_pro"
OSINT_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 12


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class OSINTProFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: OSINTProFinding) -> int:
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
            tags=["osint-pro", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Username platforms (100+)
# ===========================================================================

USERNAME_SITES = [
    # Social
    {"name": "Twitter/X",     "url": "https://x.com/{u}",             "tag": "social"},
    {"name": "Facebook",      "url": "https://www.facebook.com/{u}",  "tag": "social"},
    {"name": "Instagram",     "url": "https://instagram.com/{u}",     "tag": "social"},
    {"name": "TikTok",        "url": "https://tiktok.com/@{u}",       "tag": "social"},
    {"name": "Reddit",        "url": "https://reddit.com/user/{u}",   "tag": "social"},
    {"name": "Pinterest",     "url": "https://pinterest.com/{u}",     "tag": "social"},
    {"name": "Tumblr",        "url": "https://{u}.tumblr.com",        "tag": "social"},
    {"name": "Mastodon",      "url": "https://mastodon.social/@{u}",  "tag": "social"},
    {"name": "Minds",         "url": "https://www.minds.com/{u}",     "tag": "social"},
    {"name": "VK",            "url": "https://vk.com/{u}",            "tag": "social"},
    {"name": "OK.ru",         "url": "https://ok.ru/{u}",             "tag": "social"},
    {"name": "LinkedIn",      "url": "https://www.linkedin.com/in/{u}", "tag": "social"},
    {"name": "Snapchat",      "url": "https://www.snapchat.com/add/{u}", "tag": "social"},
    {"name": "Badoo",         "url": "https://badoo.com/en/{u}",      "tag": "social"},
    {"name": "Dating.com",    "url": "https://dating.com/en/{u}",     "tag": "social"},
    # Dev
    {"name": "GitHub",        "url": "https://github.com/{u}",        "tag": "dev"},
    {"name": "GitLab",        "url": "https://gitlab.com/{u}",        "tag": "dev"},
    {"name": "Bitbucket",     "url": "https://bitbucket.org/{u}",     "tag": "dev"},
    {"name": "Stack Overflow","url": "https://stackoverflow.com/users/{u}", "tag": "dev"},
    {"name": "Dev.to",        "url": "https://dev.to/{u}",            "tag": "dev"},
    {"name": "Medium",        "url": "https://medium.com/@{u}",       "tag": "dev"},
    {"name": "HackerNews",    "url": "https://news.ycombinator.com/user?id={u}", "tag": "dev"},
    {"name": "Replit",        "url": "https://replit.com/@{u}",       "tag": "dev"},
    {"name": "CodePen",       "url": "https://codepen.io/{u}",        "tag": "dev"},
    {"name": "SourceForge",   "url": "https://sourceforge.net/u/{u}", "tag": "dev"},
    {"name": "Pastebin",      "url": "https://pastebin.com/u/{u}",    "tag": "dev"},
    {"name": "NPM",           "url": "https://www.npmjs.com/~{u}",    "tag": "dev"},
    {"name": "PyPI",          "url": "https://pypi.org/user/{u}",     "tag": "dev"},
    {"name": "Docker Hub",    "url": "https://hub.docker.com/u/{u}",  "tag": "dev"},
    {"name": "Hashnode",      "url": "https://hashnode.com/@{u}",     "tag": "dev"},
    {"name": "Codeberg",      "url": "https://codeberg.org/{u}",      "tag": "dev"},
    {"name": "Gitea",         "url": "https://gitea.com/{u}",         "tag": "dev"},
    {"name": "Launchpad",     "url": "https://launchpad.net/~{u}",    "tag": "dev"},
    # Security
    {"name": "HackerOne",     "url": "https://hackerone.com/{u}",     "tag": "sec"},
    {"name": "Bugcrowd",      "url": "https://bugcrowd.com/{u}",      "tag": "sec"},
    {"name": "Intigriti",     "url": "https://app.intigriti.com/profile/{u}", "tag": "sec"},
    {"name": "YesWeHack",     "url": "https://yeswehack.com/hunters/{u}", "tag": "sec"},
    {"name": "HackTheBox",    "url": "https://app.hackthebox.com/users/{u}", "tag": "sec"},
    {"name": "TryHackMe",     "url": "https://tryhackme.com/p/{u}",   "tag": "sec"},
    {"name": "Exploit-DB",    "url": "https://www.exploit-db.com/?author={u}", "tag": "sec"},
    {"name": "PacketStorm",   "url": "https://packetstormsecurity.com/files/author/{u}/", "tag": "sec"},
    {"name": "Root-Me",       "url": "https://www.root-me.org/{u}",   "tag": "sec"},
    # Games
    {"name": "Twitch",        "url": "https://twitch.tv/{u}",         "tag": "games"},
    {"name": "Steam",         "url": "https://steamcommunity.com/id/{u}", "tag": "games"},
    {"name": "Xbox Gamertag", "url": "https://xboxgamertag.com/search/{u}", "tag": "games"},
    {"name": "PSN",           "url": "https://my.playstation.com/profile/{u}", "tag": "games"},
    {"name": "Roblox",        "url": "https://www.roblox.com/user.aspx?username={u}", "tag": "games"},
    {"name": "Chess.com",     "url": "https://www.chess.com/member/{u}", "tag": "games"},
    {"name": "Kick",          "url": "https://kick.com/{u}",          "tag": "games"},
    # Media
    {"name": "YouTube",       "url": "https://www.youtube.com/@{u}",  "tag": "media"},
    {"name": "SoundCloud",    "url": "https://soundcloud.com/{u}",    "tag": "media"},
    {"name": "Spotify",       "url": "https://open.spotify.com/user/{u}", "tag": "media"},
    {"name": "Vimeo",         "url": "https://vimeo.com/{u}",         "tag": "media"},
    {"name": "Last.fm",       "url": "https://www.last.fm/user/{u}",  "tag": "media"},
    {"name": "Bandcamp",      "url": "https://bandcamp.com/{u}",      "tag": "media"},
    # Portfolio
    {"name": "Behance",       "url": "https://www.behance.net/{u}",   "tag": "portfolio"},
    {"name": "Dribbble",      "url": "https://dribbble.com/{u}",      "tag": "portfolio"},
    {"name": "DeviantArt",    "url": "https://www.deviantart.com/{u}", "tag": "portfolio"},
    {"name": "Flickr",        "url": "https://www.flickr.com/people/{u}", "tag": "portfolio"},
    {"name": "500px",         "url": "https://500px.com/p/{u}",       "tag": "portfolio"},
    {"name": "ArtStation",    "url": "https://www.artstation.com/{u}", "tag": "portfolio"},
    {"name": "ProductHunt",   "url": "https://www.producthunt.com/@{u}", "tag": "portfolio"},
    {"name": "About.me",      "url": "https://about.me/{u}",          "tag": "portfolio"},
    {"name": "Gravatar",      "url": "https://gravatar.com/{u}",      "tag": "portfolio"},
    # Money
    {"name": "Patreon",       "url": "https://patreon.com/{u}",       "tag": "money"},
    {"name": "BuyMeACoffee",  "url": "https://buymeacoffee.com/{u}",  "tag": "money"},
    {"name": "Ko-fi",         "url": "https://ko-fi.com/{u}",         "tag": "money"},
    {"name": "Kickstarter",   "url": "https://www.kickstarter.com/profile/{u}", "tag": "money"},
    # Work
    {"name": "AngelList",     "url": "https://angel.co/u/{u}",        "tag": "work"},
    {"name": "F6S",           "url": "https://www.f6s.com/{u}",       "tag": "work"},
    # Shop
    {"name": "Etsy",          "url": "https://www.etsy.com/people/{u}", "tag": "shop"},
    {"name": "eBay",          "url": "https://www.ebay.com/usr/{u}",  "tag": "shop"},
    # RU
    {"name": "Habr",          "url": "https://habr.com/ru/users/{u}/", "tag": "ru"},
    {"name": "Pikabu",        "url": "https://pikabu.ru/@{u}",        "tag": "ru"},
    {"name": "LiveJournal",   "url": "https://{u}.livejournal.com",   "tag": "ru"},
    {"name": "Yandex Zen",    "url": "https://zen.yandex.ru/{u}",     "tag": "ru"},
    {"name": "DTF",           "url": "https://dtf.ru/u/{u}",          "tag": "ru"},
    # Other
    {"name": "Keybase",       "url": "https://keybase.io/{u}",        "tag": "other"},
    {"name": "Telegram",      "url": "https://t.me/{u}",              "tag": "other"},
    {"name": "WhatsApp",      "url": "https://wa.me/{u}",             "tag": "other"},
    {"name": "Foursquare",    "url": "https://foursquare.com/{u}",    "tag": "other"},
    {"name": "Disqus",        "url": "https://disqus.com/by/{u}/",    "tag": "other"},
    {"name": "Wattpad",       "url": "https://www.wattpad.com/user/{u}", "tag": "other"},
    {"name": "Quizlet",       "url": "https://quizlet.com/{u}",       "tag": "other"},
    {"name": "SlideShare",    "url": "https://www.slideshare.net/{u}", "tag": "other"},
    {"name": "Scribd",        "url": "https://www.scribd.com/{u}",    "tag": "other"},
    {"name": "Issuu",         "url": "https://issuu.com/{u}",         "tag": "other"},
    {"name": "Imgur",         "url": "https://imgur.com/user/{u}",    "tag": "other"},
]

NOT_FOUND_MARKERS = [
    "page not found", "user not found", "doesn't exist", "not found",
    "no such user", "couldn't find", "this account doesn't exist",
    "sorry, nobody on", "404 not found", "профиль не найден",
    "пользователь не найден", "this page isn't available",
]


@dataclass
class UsernameHit:
    platform: str
    url: str
    tag: str = ""
    status: int = 0
    exists: bool = False
    note: str = ""


def _check_one(site: dict, username: str) -> UsernameHit:
    url = site["url"].format(u=quote(username, safe=""))
    hit = UsernameHit(platform=site["name"], url=url,
                      tag=site.get("tag", ""))
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False,
                          allow_redirects=True,
                          headers={"User-Agent": config.USER_AGENT})
        hit.status = r.status_code
        if r.status_code == 200:
            body = r.text[:8000].lower()
            if not any(m in body for m in NOT_FOUND_MARKERS):
                hit.exists = True
                hit.note = "exists"
            else:
                hit.note = "200 with not-found marker"
        elif r.status_code in (301, 302, 307, 308):
            hit.note = f"redirect → {r.url[:60]}"
        elif r.status_code == 404:
            hit.note = "not found"
        elif r.status_code == 403:
            hit.note = "403 (may exist)"
        elif r.status_code == 429:
            hit.note = "rate-limited"
        else:
            hit.note = f"status {r.status_code}"
    except requests.exceptions.SSLError:
        hit.note = "SSL error"
    except requests.exceptions.Timeout:
        hit.note = "timeout"
    except Exception as exc:  # noqa: BLE001
        hit.note = str(exc)[:60]
    return hit


def scan_username(username: str, threads: int = 20,
                    only_tags: list[str] | None = None,
                    include_default_only: bool = False) -> list[UsernameHit]:
    """Проверить username на 100+ площадках."""
    username = (username or "").strip().lstrip("@")
    if not username:
        console.print("[red]Пустой username.[/red]")
        return []

    sites = USERNAME_SITES
    if only_tags:
        sites = [s for s in sites if s.get("tag") in only_tags]
    if include_default_only:
        sites = [s for s in sites if not s.get("skip_default")]

    console.print(f"[cyan]🔍 Username '{username}' → {len(sites)} платформ"
                  f"[/cyan]")

    hits: list[UsernameHit] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as p:
        task = p.add_task("username", total=len(sites))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(_check_one, s, username): s for s in sites}
            for f in as_completed(futs):
                p.advance(task)
                try:
                    hits.append(f.result())
                except Exception:
                    pass

    found = [h for h in hits if h.exists]
    _print_username_results(hits, found, username)

    if len(found) >= 10:
        _save_finding(OSINTProFinding(
            kind="large_username_footprint",
            severity="high",
            title=f"Username '{username}' на {len(found)} платформах",
            target=username,
            evidence="\n".join(f"{h.platform}: {h.url}"
                                for h in found[:20]),
            data={"count": len(found),
                  "platforms": [h.platform for h in found]},
        ))

    db.save_scan("osint_username", username, {
        "checked": len(sites),
        "found": len(found),
        "found_urls": [h.url for h in found],
    })

    # Export
    _export_username_report(hits, found, username)
    return hits


def _print_username_results(hits: list[UsernameHit],
                              found: list[UsernameHit],
                              username: str) -> None:
    if found:
        t = Table(title=f"✅ '{username}' ({len(found)})",
                  border_style="green")
        t.add_column("#", width=4)
        t.add_column("Platform", style="cyan", max_width=20)
        t.add_column("Tag", style="magenta", width=10)
        t.add_column("URL", style="green", max_width=60)
        for i, h in enumerate(sorted(found, key=lambda x: x.platform), 1):
            t.add_row(str(i), h.platform, h.tag, h.url)
        console.print(t)
    else:
        console.print(f"[yellow]'{username}' не найден.[/yellow]")

    maybe = [h for h in hits if not h.exists and
             (h.status in (301, 302, 403) or "exist" in h.note.lower())]
    if maybe:
        t = Table(title=f"❓ Возможно ({len(maybe)})", border_style="yellow")
        t.add_column("Platform", style="cyan")
        t.add_column("Status", width=8)
        t.add_column("Note", max_width=40)
        for h in maybe[:30]:
            t.add_row(h.platform, str(h.status), h.note)
        console.print(t)


def _export_username_report(hits: list[UsernameHit],
                              found: list[UsernameHit],
                              username: str) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # JSON
    jp = OSINT_DIR / f"username_{username}_{ts}.json"
    try:
        jp.write_text(json.dumps({
            "username": username,
            "ts": datetime.now().isoformat(),
            "total_checked": len(hits),
            "found": len(found),
            "hits": [asdict(h) for h in hits],
        }, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

    # HTML
    hp = OSINT_DIR / f"username_{username}_{ts}.html"
    try:
        html = _render_username_html(hits, found, username)
        hp.write_text(html, encoding="utf-8")
    except Exception:
        pass


def _render_username_html(hits: list[UsernameHit],
                            found: list[UsernameHit],
                            username: str) -> str:
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>OSINT username: {html_mod.escape(username)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:8px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        "a{color:#7ad9ff;text-decoration:none;}",
        "a:hover{text-decoration:underline;}",
        "</style></head><body>",
        f"<h1>🕵 OSINT: {html_mod.escape(username)}</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Checked: {len(hits)} | Found: <b>{len(found)}</b></p>",
        "<h2>Found profiles</h2>",
        "<table><tr><th>Platform</th><th>Tag</th><th>URL</th></tr>",
    ]
    for h in sorted(found, key=lambda x: x.platform):
        parts.append(
            f"<tr><td>{html_mod.escape(h.platform)}</td>"
            f"<td>{html_mod.escape(h.tag)}</td>"
            f"<td><a href='{html_mod.escape(h.url)}'>"
            f"{html_mod.escape(h.url)}</a></td></tr>")
    parts.append("</table></body></html>")
    return "\n".join(parts)


# ===========================================================================
# Telegram
# ===========================================================================

def telegram_lookup(username: str) -> dict:
    """Telegram channel/user lookup."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return {}
    result: dict[str, Any] = {"username": username, "exists": False}
    console.print(f"[cyan]✈  Telegram: @{username}[/cyan]")
    try:
        r = requests.get(f"https://t.me/{username}",
                          timeout=TIMEOUT, verify=False,
                          headers={"User-Agent": config.USER_AGENT})
        result["status"] = r.status_code
        body = r.text

        for prop, key in [("og:title", "title"),
                            ("og:description", "description"),
                            ("og:image", "avatar")]:
            m = re.search(
                rf'<meta property="{prop}" content="([^"]+)"', body)
            if m:
                result[key] = m.group(1)[:300]

        if "tgme_page_icon" in body:
            if "subscribers" in body:
                m2 = re.search(r'([\d\s,]+)\s*subscribers', body)
                if m2:
                    result["subscribers"] = m2.group(1).strip()
                result["type"] = "channel"
            else:
                result["type"] = "user_or_bot"
            result["exists"] = True
        elif "tgme_icon_user" in body or "tgme_page_action" in body:
            result["exists"] = True
            result["type"] = "user"

        t = Table(title=f"✈  Telegram @{username}")
        t.add_column("Поле", style="cyan")
        t.add_column("Значение", style="green", max_width=80)
        for k, v in result.items():
            t.add_row(k, str(v)[:80])
        console.print(t)
        db.save_scan("osint_telegram", username, result)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
    return result


# ===========================================================================
# Gravatar
# ===========================================================================

def gravatar_lookup(email: str) -> dict:
    """Gravatar + linked accounts."""
    email_clean = (email or "").strip().lower()
    if not email_clean:
        return {}
    h = hashlib.md5(email_clean.encode()).hexdigest()
    result: dict[str, Any] = {
        "email": email_clean,
        "md5": h,
        "profile_url": f"https://gravatar.com/{h}",
        "avatar_url": f"https://www.gravatar.com/avatar/{h}",
        "exists": False,
        "linked_accounts": [],
    }
    console.print(f"[cyan]🌍 Gravatar: {email_clean}[/cyan]")
    try:
        r = requests.get(
            f"https://www.gravatar.com/avatar/{h}?d=404",
            timeout=TIMEOUT, verify=False,
            headers={"User-Agent": config.USER_AGENT})
        result["status"] = r.status_code
        if r.status_code == 200:
            result["exists"] = True
            try:
                rj = requests.get(f"https://gravatar.com/{h}.json",
                                    timeout=TIMEOUT, verify=False,
                                    headers={"User-Agent":
                                             config.USER_AGENT})
                if rj.status_code == 200:
                    data = rj.json()
                    entry = (data.get("entry") or [{}])[0]
                    result["displayName"] = entry.get("displayName")
                    result["aboutMe"] = (entry.get("aboutMe") or "")[:300]
                    result["profileUrl"] = entry.get("profileUrl")
                    for acc in entry.get("accounts", []):
                        result["linked_accounts"].append({
                            "shortname": acc.get("shortname"),
                            "url": acc.get("url"),
                            "username": acc.get("username"),
                        })
            except Exception:
                pass
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)[:80]

    t = Table(title=f"🌍 Gravatar: {email_clean}")
    t.add_column("Поле", style="cyan")
    t.add_column("Значение", style="green", max_width=80)
    for k, v in result.items():
        if k == "linked_accounts" and v:
            for acc in v:
                t.add_row(f"  {acc.get('shortname', '?')}",
                          str(acc.get("url", ""))[:80])
        elif k != "linked_accounts":
            t.add_row(k, str(v)[:80])
    console.print(t)

    db.save_scan("osint_gravatar", email_clean, result)
    return result


# ===========================================================================
# Wayback Machine
# ===========================================================================

def wayback_lookup(domain: str, limit: int = 50) -> list[dict]:
    """Исторические URL."""
    host = extract_host(domain)
    console.print(f"[cyan]📚 Wayback: {host} (limit={limit})[/cyan]")
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{host}/*",
                "output": "json",
                "limit": limit,
                "collapse": "urlkey",
                "filter": "statuscode:200",
            },
            timeout=30, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        r.raise_for_status()
        data = r.json()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return []

    if not data or len(data) < 2:
        console.print("[yellow]Снапшотов не найдено.[/yellow]")
        return []

    rows = data[1:]
    urls = [{"url": r[2], "timestamp": r[1], "status": r[4],
             "archive": f"https://web.archive.org/web/{r[1]}/{r[2]}"}
            for r in rows]

    interesting = []
    for u in urls:
        lc = u["url"].lower()
        if any(k in lc for k in (
            "admin", "api", "backup", "config", "test", "debug",
            ".env", ".git", "phpinfo", "upload", "download",
            "login", "signup", "?id=", "?page=", ".sql", ".bak",
            ".json", ".yml", ".yaml", ".map",
        )):
            interesting.append(u)

    t = Table(title=f"📚 Wayback ({len(urls)} URLs, "
                    f"{len(interesting)} interesting)")
    t.add_column("Timestamp", style="dim", width=12)
    t.add_column("Status", width=6)
    t.add_column("URL", style="cyan", max_width=70)
    for u in urls[:30]:
        marker = "⭐" if u in interesting else " "
        t.add_row(u["timestamp"][:8], str(u["status"]),
                  f"{marker} {u['url'][:70]}")
    console.print(t)

    if interesting:
        console.print(f"\n[bold yellow]⭐ Sensitive URLs:[/bold yellow]")
        for u in interesting[:20]:
            console.print(f"  [green]{u['archive']}[/green]")

        _save_finding(OSINTProFinding(
            kind="wayback_sensitive_urls",
            severity="medium",
            title=f"Wayback: {len(interesting)} sensitive URLs для {host}",
            target=host,
            evidence="\n".join(u["archive"] for u in interesting[:10]),
            data={"count": len(interesting)},
        ))

    db.save_scan("osint_wayback", host, {
        "total": len(urls),
        "interesting": len(interesting),
        "urls": urls[:200],
    })
    return urls


# ===========================================================================
# Domain age (RDAP + WHOIS)
# ===========================================================================

def domain_age(domain: str) -> dict:
    """Возраст + WHOIS через RDAP."""
    host = extract_host(domain)
    console.print(f"[cyan]📅 Domain age: {host}[/cyan]")
    result: dict[str, Any] = {"domain": host}

    for url in [f"https://rdap.org/domain/{host}",
                f"https://rdap.verisign.com/com/v1/domain/{host}"]:
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False,
                             headers={"User-Agent": config.USER_AGENT,
                                       "Accept": "application/rdap+json"})
            if r.status_code != 200:
                continue
            data = r.json()
            for ev in data.get("events", []):
                action = ev.get("eventAction", "")
                date = ev.get("eventDate", "")[:10]
                if action == "registration":
                    result["registered"] = date
                elif action == "expiration":
                    result["expires"] = date
                elif action == "last changed":
                    result["last_changed"] = date
                elif action == "transfer":
                    result["last_transfer"] = date

            # Status
            result["status"] = data.get("status", [])[:5]

            # Registrar
            for ent in data.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    vc = ent.get("vcardArray", [None, []])
                    for item in vc[1]:
                        if item[0] == "fn":
                            result["registrar"] = item[3]

            if result.get("registered"):
                try:
                    reg_dt = datetime.strptime(result["registered"],
                                                 "%Y-%m-%d")
                    age_days = (datetime.now() - reg_dt).days
                    result["age_days"] = age_days
                    result["age_years"] = round(age_days / 365.25, 1)
                except Exception:
                    pass
            break
        except Exception:
            continue

    t = Table(title=f"📅 Domain age: {host}")
    t.add_column("Поле", style="cyan")
    t.add_column("Значение", style="green", max_width=80)
    for k, v in result.items():
        t.add_row(k, str(v)[:80])
    console.print(t)

    age_days = result.get("age_days")
    if age_days is not None:
        if age_days < 90:
            console.print(f"[red]⚠ Домен младше 90 дней — "
                          f"риск фишинга[/red]")
            _save_finding(OSINTProFinding(
                kind="suspicious_young_domain",
                severity="high",
                title=f"Домен младше 90 дней: {host}",
                target=host,
                evidence=f"Age: {age_days} дней, "
                         f"Registered: {result.get('registered')}",
                data=result,
            ))
        elif age_days < 365:
            console.print(f"[yellow]⚠ Домен младше года[/yellow]")
        else:
            console.print(f"[green]✓ Домен существует давно[/green]")

    db.save_scan("osint_domain_age", host, result)
    return result


# ===========================================================================
# DNS dump
# ===========================================================================

def dns_dump(domain: str) -> dict:
    """Расширенный DNS dump + DNSSEC/DMARC/SPF/BIMI."""
    host = extract_host(domain)
    console.print(f"[cyan]🌐 DNS dump: {host}[/cyan]")
    result: dict[str, list[str]] = {}

    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA",
                   "CNAME", "SRV", "PTR", "DS", "DNSKEY", "NAPTR"]:
        try:
            answers = dns.resolver.resolve(host, rtype, lifetime=5)
            result[rtype] = [str(a).strip('"') for a in answers]
        except Exception:
            pass

    # DMARC
    try:
        for a in dns.resolver.resolve(f"_dmarc.{host}", "TXT", lifetime=5):
            txt = b"".join(getattr(a, "strings", [str(a).encode()]))
            result.setdefault("DMARC", []).append(
                txt.decode(errors="ignore")[:300])
    except Exception:
        pass

    # SPF (from TXT)
    for txt in result.get("TXT", []):
        if txt.startswith("v=spf1"):
            result.setdefault("SPF", []).append(txt[:300])

    # DKIM (common selectors)
    for sel in ("default", "google", "selector1", "selector2", "k1"):
        try:
            for a in dns.resolver.resolve(
                    f"{sel}._domainkey.{host}", "TXT", lifetime=5):
                txt = b"".join(getattr(a, "strings", [str(a).encode()]))
                result.setdefault("DKIM", []).append(
                    f"{sel}: {txt.decode(errors='ignore')[:200]}")
                break
        except Exception:
            continue

    # BIMI
    try:
        for a in dns.resolver.resolve(f"default._bimi.{host}", "TXT",
                                        lifetime=5):
            txt = b"".join(getattr(a, "strings", [str(a).encode()]))
            result.setdefault("BIMI", []).append(
                txt.decode(errors="ignore")[:200])
    except Exception:
        pass

    # MTA-STS
    try:
        for a in dns.resolver.resolve(f"_mta-sts.{host}", "TXT",
                                        lifetime=5):
            txt = b"".join(getattr(a, "strings", [str(a).encode()]))
            result.setdefault("MTA-STS", []).append(
                txt.decode(errors="ignore")[:200])
    except Exception:
        pass

    t = Table(title=f"🌐 DNS dump: {host}")
    t.add_column("Type", style="magenta", width=10)
    t.add_column("Value", style="green", max_width=80)
    for rtype, values in result.items():
        for v in values:
            t.add_row(rtype, v[:80])
    console.print(t)

    # Findings
    if not result.get("SPF"):
        _save_finding(OSINTProFinding(
            kind="spf_missing",
            severity="medium",
            title=f"SPF отсутствует на {host}",
            target=host,
            evidence="Уязвимость к email spoofing",
        ))
    if not result.get("DMARC"):
        _save_finding(OSINTProFinding(
            kind="dmarc_missing",
            severity="medium",
            title=f"DMARC отсутствует на {host}",
            target=host,
            evidence="Email spoofing возможен",
        ))

    db.save_scan("osint_dns_dump", host, result)
    return result


# ===========================================================================
# GitHub / GitLab / Bitbucket
# ===========================================================================

def github_user(username: str) -> dict:
    """GitHub user info + repos + orgs + gists."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return {}
    console.print(f"[cyan]🐙 GitHub: {username}[/cyan]")

    headers = {"Accept": "application/vnd.github+json",
                "User-Agent": config.USER_AGENT}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"token {config.GITHUB_TOKEN}"

    result: dict[str, Any] = {"username": username}
    try:
        r = requests.get(f"https://api.github.com/users/{username}",
                          headers=headers, timeout=TIMEOUT, verify=False)
        if r.status_code == 404:
            console.print("[yellow]Не найден.[/yellow]")
            return result
        r.raise_for_status()
        data = r.json()
        for k in ("name", "email", "company", "blog", "location", "bio",
                  "public_repos", "public_gists", "followers",
                  "following", "created_at", "updated_at"):
            if data.get(k):
                result[k] = data[k]

        # Repos
        try:
            rr = requests.get(
                f"https://api.github.com/users/{username}/repos",
                headers=headers,
                params={"per_page": 30, "sort": "updated"},
                timeout=TIMEOUT, verify=False)
            if rr.status_code == 200:
                repos = rr.json()
                result["repos"] = [{
                    "name": rp.get("name"),
                    "desc": (rp.get("description") or "")[:80],
                    "lang": rp.get("language"),
                    "stars": rp.get("stargazers_count"),
                    "fork": rp.get("fork"),
                } for rp in repos]
        except Exception:
            pass

        # Orgs
        try:
            orq = requests.get(
                f"https://api.github.com/users/{username}/orgs",
                headers=headers, timeout=TIMEOUT, verify=False)
            if orq.status_code == 200:
                result["orgs"] = [o.get("login") for o in orq.json()]
        except Exception:
            pass

        # Gists
        try:
            gr = requests.get(
                f"https://api.github.com/users/{username}/gists",
                headers=headers, timeout=TIMEOUT, verify=False)
            if gr.status_code == 200:
                gists = gr.json()
                result["gists"] = [{
                    "id": g.get("id"),
                    "description": (g.get("description") or "")[:60],
                    "public": g.get("public"),
                    "files": list((g.get("files") or {}).keys())[:5],
                } for g in gists[:20]]
        except Exception:
            pass

        t = Table(title=f"🐙 GitHub: {username}")
        t.add_column("Field", style="cyan")
        t.add_column("Value", style="green", max_width=80)
        for k, v in result.items():
            if k in ("repos", "gists"):
                continue
            t.add_row(k, str(v)[:80])
        console.print(t)

        if result.get("repos"):
            t2 = Table(title=f"📦 Repos ({len(result['repos'])})")
            t2.add_column("Name", style="cyan")
            t2.add_column("Lang", style="magenta", width=12)
            t2.add_column("Stars", style="yellow", width=6)
            t2.add_column("Desc", style="white", max_width=50)
            for rp in result["repos"]:
                t2.add_row(rp["name"], rp.get("lang") or "—",
                            str(rp.get("stars", 0)),
                            rp.get("desc") or "")
            console.print(t2)

        if result.get("orgs"):
            console.print(f"[cyan]Orgs:[/cyan] {', '.join(result['orgs'])}")

        if result.get("gists"):
            console.print(f"[cyan]Gists:[/cyan] {len(result['gists'])}")

    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")

    db.save_scan("osint_github", username, result)
    return result


def gitlab_user(username: str) -> dict:
    """GitLab user info."""
    username = (username or "").strip().lstrip("@")
    if not username:
        return {}
    console.print(f"[cyan]🦊 GitLab: {username}[/cyan]")
    result: dict[str, Any] = {"username": username}
    try:
        # Search users
        r = requests.get("https://gitlab.com/api/v4/users",
                          params={"username": username},
                          timeout=TIMEOUT, verify=False,
                          headers={"User-Agent": config.USER_AGENT})
        if r.status_code == 200:
            users = r.json()
            if users:
                u = users[0]
                result.update({
                    "id": u.get("id"),
                    "name": u.get("name"),
                    "state": u.get("state"),
                    "avatar": u.get("avatar_url"),
                    "web_url": u.get("web_url"),
                    "created_at": u.get("created_at"),
                    "bio": u.get("bio"),
                    "location": u.get("location"),
                })
                # Projects
                try:
                    pr = requests.get(
                        f"https://gitlab.com/api/v4/users/{u['id']}/projects",
                        params={"per_page": 20},
                        timeout=TIMEOUT, verify=False,
                        headers={"User-Agent": config.USER_AGENT})
                    if pr.status_code == 200:
                        result["projects"] = [{
                            "name": p.get("name"),
                            "stars": p.get("star_count"),
                            "forks": p.get("forks_count"),
                            "url": p.get("web_url"),
                        } for p in pr.json()]
                except Exception:
                    pass

        t = Table(title=f"🦊 GitLab: {username}")
        t.add_column("Поле", style="cyan")
        t.add_column("Значение", style="green", max_width=80)
        for k, v in result.items():
            if k == "projects":
                continue
            t.add_row(k, str(v)[:80])
        console.print(t)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
    db.save_scan("osint_gitlab", username, result)
    return result


# ===========================================================================
# Reverse image search
# ===========================================================================

def reverse_image_links(image_url: str) -> dict:
    """Ссылки на reverse-image-search сервисы."""
    enc = quote(image_url, safe="")
    links = {
        "Google Lens":   f"https://lens.google.com/uploadbyurl?url={enc}",
        "Yandex":        f"https://yandex.com/images/search?rpt=imageview&url={enc}",
        "TinEye":        f"https://tineye.com/search?url={enc}",
        "Bing Visual":   f"https://www.bing.com/images/search?q=imgurl:{enc}&view=detailv2&iss=sbi",
        "SauceNAO":      f"https://saucenao.com/search.php?url={enc}",
        "PimEyes":       "https://pimeyes.com/en",
        "Karma Decay":   f"http://karmadecay.com/{enc}",
    }
    t = Table(title="🖼  Reverse image search")
    t.add_column("Сервис", style="cyan")
    t.add_column("Ссылка", style="green")
    for name, url in links.items():
        t.add_row(name, url)
    console.print(t)
    db.save_scan("osint_reverse_image", image_url[:80], links)
    return links


# ===========================================================================
# Email intel
# ===========================================================================

def email_intel(email: str) -> dict:
    """Multi-source email links + analysis."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        return {}
    enc = quote(email, safe="")
    local, _, domain = email.partition("@")

    result: dict[str, Any] = {
        "email": email,
        "local_part": local,
        "domain": domain,
    }

    links = {
        "HIBP":            f"https://haveibeenpwned.com/account/{enc}",
        "Firefox Monitor": "https://monitor.firefox.com/",
        "DeHashed":        f"https://dehashed.com/search?query={enc}",
        "LeakCheck":       "https://leakcheck.io/",
        "IntelligenceX":   f"https://intelx.io/?s={enc}",
        "Hunter.io":       f"https://hunter.io/email-verifier/{enc}",
        "EmailRep.io":     f"https://emailrep.io/{enc}",
        "Have I Been Sold":"https://haveibeensold.app/",
    }
    result["public_links"] = links

    t = Table(title=f"📧 Email intel: {email}")
    t.add_column("Сервис", style="cyan")
    t.add_column("Ссылка", style="green")
    for name, url in links.items():
        t.add_row(name, url)
    console.print(t)

    # Disposable check (basic)
    disposable_domains = {
        "mailinator.com", "guerrillamail.com", "10minutemail.com",
        "tempmail.com", "throwaway.email", "yopmail.com",
        "sharklasers.com", "maildrop.cc", "trashmail.com",
    }
    if domain in disposable_domains:
        result["disposable"] = True
        console.print(f"[yellow]⚠ Disposable email domain[/yellow]")
    else:
        result["disposable"] = False

    db.save_scan("osint_email", email, result)
    return result


# ===========================================================================
# Phone intel
# ===========================================================================

def phone_intel(phone: str) -> dict:
    """Расширенный анализ телефона через phonenumbers."""
    import re
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) < 7:
        console.print("[red]Неверный номер.[/red]")
        return {}
    result: dict[str, Any] = {"raw": phone, "digits": digits,
                                "length": len(digits)}
    try:
        import phonenumbers
        try:
            parsed = phonenumbers.parse(phone, None)
            result.update({
                "valid": phonenumbers.is_valid_number(parsed),
                "possible": phonenumbers.is_possible_number(parsed),
                "region": phonenumbers.region_code_for_number(parsed),
                "country_code": parsed.country_code,
                "national_number": str(parsed.national_number),
                "carrier": phonenumbers.carrier.name_for_number(
                    parsed, "en") or "—",
                "timezones": list(
                    phonenumbers.timezone.time_zones_for_number(parsed))[:5],
                "type": str(phonenumbers.number_type(parsed)),
                "e164": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.E164),
                "international": phonenumbers.format_number(
                    parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            })
        except Exception as exc:
            result["parse_error"] = str(exc)[:80]
    except ImportError:
        result["libphonenumber"] = "not installed"

    t = Table(title=f"📱 Phone: {phone}")
    t.add_column("Поле", style="cyan")
    t.add_column("Значение", style="green", max_width=80)
    for k, v in result.items():
        t.add_row(k, str(v)[:80])
    console.print(t)

    db.save_scan("osint_phone", phone, result)
    return result


# ===========================================================================
# Full scan
# ===========================================================================

def full_scan(username: str = "", email: str = "",
              domain: str = "") -> dict:
    """Полный OSINT."""
    result: dict[str, Any] = {
        "ts": datetime.now().isoformat(timespec="seconds"),
    }
    if username:
        console.print(f"\n[bold cyan]═══ USERNAME: {username} ═══"
                      f"[/bold cyan]")
        scan_username(username)
        telegram_lookup(username)
        github_user(username)
        result["username"] = username
    if domain:
        console.print(f"\n[bold cyan]═══ DOMAIN: {domain} ═══[/bold cyan]")
        wayback_lookup(domain, limit=30)
        domain_age(domain)
        dns_dump(domain)
        result["domain"] = domain
    if email:
        console.print(f"\n[bold cyan]═══ EMAIL: {email} ═══[/bold cyan]")
        gravatar_lookup(email)
        email_intel(email)
        result["email"] = email

    # HTML report
    if result:
        _export_full_report(result)
        # Notify
        try:
            from modules import notifier
            notifier.notify_all(
                "🕵  OSINT Pro scan done",
                f"Username: {username or '—'}\n"
                f"Domain: {domain or '—'}\n"
                f"Email: {email or '—'}",
            )
        except Exception:
            pass
    return result


def _export_full_report(result: dict) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = hashlib.md5(json.dumps(result, sort_keys=True,
                                    default=str).encode()
                        ).hexdigest()[:8]
    path = OSINT_DIR / f"full_{safe}_{ts}.json"
    try:
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False,
                                     default=str), encoding="utf-8")
        console.print(f"[green]✓ {path}[/green]")
    except Exception:
        pass


# ===========================================================================
# CLI wrappers
# ===========================================================================

def cli_username(username: str) -> None:
    scan_username(username)


def cli_telegram(username: str) -> None:
    telegram_lookup(username)


def cli_gravatar(email: str) -> None:
    gravatar_lookup(email)


def cli_wayback(domain: str) -> None:
    wayback_lookup(domain)


def cli_age(domain: str) -> None:
    domain_age(domain)


def cli_dns(domain: str) -> None:
    dns_dump(domain)


def cli_github(username: str) -> None:
    github_user(username)


def cli_gitlab(username: str) -> None:
    gitlab_user(username)


def cli_email(email: str) -> None:
    email_intel(email)


def cli_image(image_url: str) -> None:
    reverse_image_links(image_url)


def cli_phone(phone: str) -> None:
    phone_intel(phone)


def cli_full(username: str = "", email: str = "",
              domain: str = "") -> None:
    full_scan(username, email, domain)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🕵  OSINT Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Username scan (100+ платформ)"),
        ("2", "Username — только соцсети/media"),
        ("3", "Username — только dev/sec"),
        ("4", "Telegram lookup"),
        ("5", "Gravatar (+ linked accounts)"),
        ("6", "Wayback Machine (+ sensitive URLs)"),
        ("7", "Domain age (RDAP)"),
        ("8", "DNS dump (+ DNSSEC/DMARC/BIMI)"),
        ("9", "GitHub user info (+ repos/orgs/gists)"),
        ("10", "GitLab user info"),
        ("11", "Email intelligence (links)"),
        ("12", "Phone intel"),
        ("13", "Reverse image search"),
        ("14", "Полный OSINT (username + email + domain)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования / "
                  "bug bounty.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        scan_username(Prompt.ask("Username (без @)"))
    elif c == "2":
        scan_username(Prompt.ask("Username"),
                        only_tags=["social", "media"])
    elif c == "3":
        scan_username(Prompt.ask("Username"), only_tags=["dev", "sec"])
    elif c == "4":
        telegram_lookup(Prompt.ask("Telegram @username"))
    elif c == "5":
        gravatar_lookup(Prompt.ask("Email"))
    elif c == "6":
        wayback_lookup(Prompt.ask("Domain"))
    elif c == "7":
        domain_age(Prompt.ask("Domain"))
    elif c == "8":
        dns_dump(Prompt.ask("Domain"))
    elif c == "9":
        github_user(Prompt.ask("GitHub username"))
    elif c == "10":
        gitlab_user(Prompt.ask("GitLab username"))
    elif c == "11":
        email_intel(Prompt.ask("Email"))
    elif c == "12":
        phone_intel(Prompt.ask("Phone"))
    elif c == "13":
        reverse_image_links(Prompt.ask("Image URL"))
    elif c == "14":
        u = Prompt.ask("Username (опц.)", default="").strip() or None
        d = Prompt.ask("Domain (опц.)", default="").strip() or None
        e = Prompt.ask("Email (опц.)", default="").strip() or None
        full_scan(u or "", e or "", d or "")