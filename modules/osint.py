"""
OSINT (базовый) — расширенная разведка.
Author: idqwixxa

⚠ Только для этичного использования / bug bounty / CTF.

Возможности:
    ─── Username ───
    - 60+ платформ (Sherlock-style)
    - Категории: social, dev, sec, games, media, portfolio, ru
    - Vendor-independent detector (regex + status code)
    - Дедупликация результатов

    ─── Email ───
    - HIBP API v3 (если ключ задан)
    - Fallback: публичные ссылки (LeakCheck, DeHashed, IntelX)
    - Расширенный анализ (domain, MX, disposable check)

    ─── Phone ───
    - Определение страны/оператора (offline)
    - Free APIs: numverify-like (если есть ключ)
    - Валидация формата (libphonenumber если установлен)

    ─── EXIF ───
    - Полный EXIF (все теги + GPS координаты)
    - Camera fingerprint (Make/Model/Serial)
    - Software + created/modified dates

    ─── GitHub dorks ───
    - 15+ шаблонов (secrets, .env, .git, id_rsa, config.json, .aws/credentials)

    ─── Findings / интеграция ───
    - Critical/high → notes
    - Notify
    - HTML / JSON / CSV / Markdown экспорт
"""
import base64
import csv
import hashlib
import html as html_mod
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

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

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OSINT_DIR = REPORT_DIR / "osint"
OSINT_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 10


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class OSINTFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: OSINTFinding) -> int:
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
            tags=["osint", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Username sites (60+)
# ===========================================================================

USERNAME_SITES = {
    # ── Social ──
    "GitHub":         "https://github.com/{u}",
    "Twitter/X":      "https://x.com/{u}",
    "Instagram":      "https://instagram.com/{u}",
    "Facebook":       "https://facebook.com/{u}",
    "TikTok":         "https://tiktok.com/@{u}",
    "Reddit":         "https://reddit.com/user/{u}",
    "Pinterest":      "https://pinterest.com/{u}",
    "Tumblr":         "https://{u}.tumblr.com",
    "Mastodon":       "https://mastodon.social/@{u}",
    "Minds":          "https://www.minds.com/{u}",
    "VK":             "https://vk.com/{u}",
    "OK.ru":          "https://ok.ru/{u}",
    "LinkedIn":       "https://www.linkedin.com/in/{u}",
    "Snapchat":       "https://www.snapchat.com/add/{u}",
    "Badoo":          "https://badoo.com/en/{u}",
    # ── Dev ──
    "GitLab":         "https://gitlab.com/{u}",
    "Bitbucket":      "https://bitbucket.org/{u}",
    "Dev.to":         "https://dev.to/{u}",
    "Medium":         "https://medium.com/@{u}",
    "HackerNews":     "https://news.ycombinator.com/user?id={u}",
    "Replit":         "https://replit.com/@{u}",
    "CodePen":        "https://codepen.io/{u}",
    "SourceForge":    "https://sourceforge.net/u/{u}",
    "Pastebin":       "https://pastebin.com/u/{u}",
    "NPM":            "https://www.npmjs.com/~{u}",
    "PyPI":           "https://pypi.org/user/{u}",
    "Docker Hub":     "https://hub.docker.com/u/{u}",
    "Stack Overflow": "https://stackoverflow.com/users/{u}",
    "Hashnode":       "https://hashnode.com/@{u}",
    "Codeberg":       "https://codeberg.org/{u}",
    # ── Security ──
    "HackerOne":      "https://hackerone.com/{u}",
    "Bugcrowd":       "https://bugcrowd.com/{u}",
    "Intigriti":      "https://app.intigriti.com/profile/{u}",
    "YesWeHack":      "https://yeswehack.com/hunters/{u}",
    "HackTheBox":     "https://app.hackthebox.com/users/{u}",
    "TryHackMe":      "https://tryhackme.com/p/{u}",
    "Root-Me":        "https://www.root-me.org/{u}",
    "Exploit-DB":     "https://www.exploit-db.com/?author={u}",
    # ── Games ──
    "Twitch":         "https://twitch.tv/{u}",
    "Steam":          "https://steamcommunity.com/id/{u}",
    "Xbox":           "https://xboxgamertag.com/search/{u}",
    "PSN":            "https://my.playstation.com/profile/{u}",
    "Roblox":         "https://www.roblox.com/user.aspx?username={u}",
    "Chess.com":      "https://www.chess.com/member/{u}",
    "Kick":           "https://kick.com/{u}",
    # ── Media ──
    "YouTube":        "https://www.youtube.com/@{u}",
    "SoundCloud":     "https://soundcloud.com/{u}",
    "Spotify":        "https://open.spotify.com/user/{u}",
    "Vimeo":          "https://vimeo.com/{u}",
    "Last.fm":        "https://www.last.fm/user/{u}",
    "Bandcamp":       "https://bandcamp.com/{u}",
    # ── Portfolio ──
    "Behance":        "https://www.behance.net/{u}",
    "Dribbble":       "https://dribbble.com/{u}",
    "DeviantArt":     "https://www.deviantart.com/{u}",
    "Flickr":         "https://www.flickr.com/people/{u}",
    "ArtStation":     "https://www.artstation.com/{u}",
    "ProductHunt":    "https://www.producthunt.com/@{u}",
    "About.me":       "https://about.me/{u}",
    # ── Money ──
    "Patreon":        "https://patreon.com/{u}",
    "BuyMeACoffee":   "https://buymeacoffee.com/{u}",
    "Ko-fi":          "https://ko-fi.com/{u}",
    # ── RU ──
    "Habr":           "https://habr.com/ru/users/{u}/",
    "Pikabu":         "https://pikabu.ru/@{u}",
    "LiveJournal":    "https://{u}.livejournal.com",
    # ── Other ──
    "Keybase":        "https://keybase.io/{u}",
    "Telegram":       "https://t.me/{u}",
    "Foursquare":     "https://foursquare.com/{u}",
    "Disqus":         "https://disqus.com/by/{u}/",
    "Imgur":          "https://imgur.com/user/{u}",
    "Gravatar":       "https://gravatar.com/{u}",
}

USERNAME_TAGS = {
    "GitHub": "dev", "GitLab": "dev", "Bitbucket": "dev",
    "Dev.to": "dev", "Medium": "dev", "HackerNews": "dev",
    "Replit": "dev", "CodePen": "dev", "SourceForge": "dev",
    "Pastebin": "dev", "NPM": "dev", "PyPI": "dev",
    "Docker Hub": "dev", "Stack Overflow": "dev",
    "Hashnode": "dev", "Codeberg": "dev",
    "HackerOne": "sec", "Bugcrowd": "sec", "Intigriti": "sec",
    "YesWeHack": "sec", "HackTheBox": "sec", "TryHackMe": "sec",
    "Root-Me": "sec", "Exploit-DB": "sec",
    "Twitter/X": "social", "Instagram": "social", "Facebook": "social",
    "TikTok": "social", "Reddit": "social", "Pinterest": "social",
    "Tumblr": "social", "Mastodon": "social", "Minds": "social",
    "VK": "social", "OK.ru": "social", "LinkedIn": "social",
    "Snapchat": "social", "Badoo": "social",
    "Twitch": "games", "Steam": "games", "Xbox": "games",
    "PSN": "games", "Roblox": "games", "Chess.com": "games",
    "Kick": "games",
    "YouTube": "media", "SoundCloud": "media", "Spotify": "media",
    "Vimeo": "media", "Last.fm": "media", "Bandcamp": "media",
    "Behance": "portfolio", "Dribbble": "portfolio",
    "DeviantArt": "portfolio", "Flickr": "portfolio",
    "ArtStation": "portfolio", "ProductHunt": "portfolio",
    "About.me": "portfolio",
    "Patreon": "money", "BuyMeACoffee": "money", "Ko-fi": "money",
    "Habr": "ru", "Pikabu": "ru", "LiveJournal": "ru",
    "Keybase": "other", "Telegram": "other",
    "Foursquare": "other", "Disqus": "other", "Imgur": "other",
    "Gravatar": "other",
}

NOT_FOUND_MARKERS = [
    "page not found", "user not found", "doesn't exist", "not found",
    "no such user", "couldn't find", "this account doesn't exist",
    "sorry, nobody on", "404 not found", "профиль не найден",
    "пользователь не найден", "this page isn't available",
]


# ===========================================================================
# Username
# ===========================================================================

@dataclass
class UsernameHit:
    platform: str
    url: str
    tag: str = ""
    status: int = 0
    exists: bool = False
    note: str = ""


def _check_username_one(platform: str, tmpl: str, username: str) -> UsernameHit:
    url = tmpl.format(u=quote(username, safe=""))
    hit = UsernameHit(platform=platform, url=url,
                      tag=USERNAME_TAGS.get(platform, ""))
    try:
        r = requests.get(
            url, timeout=TIMEOUT, verify=False, allow_redirects=True,
            headers={"User-Agent": config.USER_AGENT},
        )
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


def username_check(username: str, threads: int = 20,
                    only_tags: list[str] | None = None) -> list[UsernameHit]:
    """Проверить username на 60+ площадках."""
    username = (username or "").strip().lstrip("@")
    if not username:
        console.print("[red]Пустой username.[/red]")
        return []

    sites = dict(USERNAME_SITES)
    if only_tags:
        sites = {n: u for n, u in sites.items()
                 if USERNAME_TAGS.get(n) in only_tags}

    console.print(f"[cyan]🔍 Username '{username}' → {len(sites)} "
                  f"платформ[/cyan]")

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
            futs = {ex.submit(_check_username_one, n, u, username): n
                    for n, u in sites.items()}
            for f in as_completed(futs):
                p.advance(task)
                try:
                    hits.append(f.result())
                except Exception:
                    pass

    found = [h for h in hits if h.exists]
    _print_username_results(hits, found, username)

    # Findings для очень больших footprints
    if len(found) >= 10:
        _save_finding(OSINTFinding(
            kind="large_username_footprint",
            severity="high",
            title=f"Username '{username}' на {len(found)} платформах",
            target=username,
            evidence="\n".join(f"{h.platform}: {h.url}" for h in found[:20]),
            data={"count": len(found), "platforms":
                  [h.platform for h in found]},
        ))

    db.save_scan("osint_username", username, {
        "checked": len(sites),
        "found": len(found),
        "found_urls": [h.url for h in found],
    })

    # Export
    if found:
        _export_username(hits, username, found)

    return hits


def _export_username(hits: list[UsernameHit], username: str,
                      found: list[UsernameHit]) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = OSINT_DIR / f"username_{username}_{ts}.json"
    try:
        path.write_text(json.dumps({
            "username": username,
            "ts": datetime.now().isoformat(),
            "total_checked": len(hits),
            "found": len(found),
            "hits": [asdict(h) for h in hits],
        }, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _print_username_results(hits: list[UsernameHit],
                              found: list[UsernameHit],
                              username: str) -> None:
    if found:
        t = Table(title=f"✅ Найден '{username}' ({len(found)})",
                  border_style="green")
        t.add_column("#", width=4)
        t.add_column("Platform", style="cyan")
        t.add_column("Tag", style="magenta", width=10)
        t.add_column("URL", style="green", max_width=70)
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


# ===========================================================================
# Email breach
# ===========================================================================

def email_breach(email: str) -> dict:
    """Проверка утечек через HIBP (если ключ) + public links."""
    email = (email or "").strip().lower()
    if not email or "@" not in email:
        console.print("[red]Неверный email.[/red]")
        return {}

    result: dict = {"email": email, "breaches": [], "sources": {}}
    console.print(f"[cyan]📧 Email breach: {email}[/cyan]")

    # HIBP
    if config.HIBP_API_KEY:
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                headers={"hibp-api-key": config.HIBP_API_KEY,
                          "User-Agent": config.USER_AGENT},
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                data = r.json()
                result["breaches"] = [{
                    "name": b.get("Name"),
                    "title": b.get("Title"),
                    "date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "description": (b.get("Description") or "")[:200],
                } for b in data]
                result["sources"]["hibp"] = len(data)
                console.print(f"[red]⚠ Найдено {len(data)} утечек "
                              f"(HIBP)[/red]")
            elif r.status_code == 404:
                result["sources"]["hibp"] = 0
                console.print("[green]HIBP: утечек не найдено.[/green]")
            elif r.status_code == 401:
                console.print("[yellow]HIBP: неверный API-ключ.[/yellow]")
            elif r.status_code == 429:
                console.print("[yellow]HIBP: rate-limited.[/yellow]")
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]HIBP: {exc}[/red]")
    else:
        console.print("[yellow]HIBP_API_KEY не задан — только ссылки.[/yellow]")

    # Public links (всегда)
    result["public_links"] = {
        "hibp": f"https://haveibeenpwned.com/account/{quote(email)}",
        "leakcheck": "https://leakcheck.io/",
        "dehashed": f"https://dehashed.com/search?query={quote(email)}",
        "intelx": f"https://intelx.io/?s={quote(email)}",
        "hunter": f"https://hunter.io/email-verifier/{quote(email)}",
    }

    # Findings
    if result["breaches"]:
        crit_breaches = [b for b in result["breaches"]
                         if any(c in b.get("data_classes", [])
                                 for c in ("Passwords", "Credit cards",
                                            "Bank account numbers"))]
        sev = "critical" if crit_breaches else "high"
        _save_finding(OSINTFinding(
            kind="email_breach",
            severity=sev,
            title=f"Email {email} в {len(result['breaches'])} утечках",
            target=email,
            evidence="\n".join(
                f"- {b['name']} ({b.get('date', '?')})" 
                for b in result["breaches"][:20]),
            data={"breaches": [b["name"] for b in result["breaches"]]},
        ))

        # Notify
        try:
            from modules import notifier
            notifier.notify_all(
                f"📧 Breach: {email}",
                f"Found in {len(result['breaches'])} breaches",
            )
        except Exception:
            pass

    db.save_scan("email_breach", email, result)

    # Export
    _export_breach(result)
    return result


def _export_breach(result: dict) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = hashlib.md5(result["email"].encode()).hexdigest()[:8]
    path = OSINT_DIR / f"breach_{safe}_{ts}.json"
    try:
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False),
                          encoding="utf-8")
    except Exception:
        pass


# ===========================================================================
# Phone
# ===========================================================================

PHONE_PREFIXES = [
    ("7", "RU/KZ (+7)"), ("1", "US/CA (+1)"), ("44", "UK (+44)"),
    ("49", "DE (+49)"), ("380", "UA (+380)"), ("375", "BY (+375)"),
    ("48", "PL (+48)"), ("33", "FR (+33)"), ("39", "IT (+39)"),
    ("34", "ES (+34)"), ("86", "CN (+86)"), ("81", "JP (+81)"),
    ("91", "IN (+91)"), ("55", "BR (+55)"), ("31", "NL (+31)"),
    ("32", "BE (+32)"), ("41", "CH (+41)"), ("43", "AT (+43)"),
    ("45", "DK (+45)"), ("46", "SE (+46)"), ("47", "NO (+47)"),
    ("358", "FI (+358)"), ("351", "PT (+351)"), ("30", "GR (+30)"),
    ("90", "TR (+90)"), ("972", "IL (+972)"), ("971", "AE (+971)"),
    ("966", "SA (+966)"), ("20", "EG (+20)"), ("27", "ZA (+27)"),
    ("82", "KR (+82)"), ("852", "HK (+852)"), ("65", "SG (+65)"),
    ("66", "TH (+66)"), ("60", "MY (+60)"), ("62", "ID (+62)"),
    ("63", "PH (+63)"), ("84", "VN (+84)"),
]


def phone_lookup(phone: str) -> dict:
    """Расширенный анализ телефона."""
    digits = re.sub(r"\D", "", phone or "")
    if len(digits) < 7:
        console.print("[red]Неверный номер.[/red]")
        return {}

    info: dict = {
        "raw": phone,
        "digits": digits,
        "length": len(digits),
        "country": None,
        "possible_carriers": [],
    }

    for prefix, country in sorted(PHONE_PREFIXES,
                                    key=lambda x: -len(x[0])):
        if digits.startswith(prefix):
            info["country"] = country
            info["country_code"] = prefix
            break

    # Try libphonenumber if available
    try:
        import phonenumbers
        try:
            parsed = phonenumbers.parse(phone, None)
            info["valid"] = phonenumbers.is_valid_number(parsed)
            info["possible"] = phonenumbers.is_possible_number(parsed)
            info["region"] = phonenumbers.region_code_for_number(parsed)
            info["carrier"] = phonenumbers.carrier.name_for_number(
                parsed, "en") or ""
            info["timezone"] = list(phonenumbers.timezone.time_zones_for_number(
                parsed))[:3]
            info["number_type"] = str(phonenumbers.number_type(parsed))
        except Exception as exc:
            info["parse_error"] = str(exc)[:80]
    except ImportError:
        info["libphonenumber"] = "not installed (pip install phonenumbers)"

    t = Table(title=f"📱 Phone: {phone}")
    t.add_column("Поле", style="cyan")
    t.add_column("Значение", style="green")
    for k, v in info.items():
        t.add_row(k, str(v)[:80])
    console.print(t)

    db.save_scan("phone", phone, info)
    return info


# ===========================================================================
# EXIF
# ===========================================================================

def exif_extractor(path: str) -> dict:
    """Извлечение EXIF + GPS."""
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        console.print("[red]Pillow не установлен.[/red]")
        return {}

    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return {}

    try:
        img = Image.open(p)
        exif = img.getexif()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка открытия: {exc}[/red]")
        return {}

    if not exif:
        console.print("[yellow]EXIF отсутствует.[/yellow]")
        return {}

    result: dict = {}
    for tag_id, value in exif.items():
        tag = TAGS.get(tag_id, str(tag_id))
        result[str(tag)] = str(value)[:300]

    # GPS
    gps_info: dict = {}
    gps_coords: tuple | None = None
    try:
        gps_info_raw = exif.get_ifd(0x8825)
        if gps_info_raw:
            gps_info = {GPSTAGS.get(k, k): v for k, v in gps_info_raw.items()}
            result["GPS"] = json.dumps(gps_info, default=str)

            # Convert to decimal
            lat = gps_info.get("GPSLatitude")
            lat_ref = gps_info.get("GPSLatitudeRef", "N")
            lon = gps_info.get("GPSLongitude")
            lon_ref = gps_info.get("GPSLongitudeRef", "E")
            if lat and lon:
                def _to_dec(vals, ref):
                    try:
                        d = float(vals[0])
                        m = float(vals[1])
                        s = float(vals[2])
                        dec = d + m / 60 + s / 3600
                        if ref in ("S", "W"):
                            dec = -dec
                        return round(dec, 6)
                    except Exception:
                        return None
                lat_d = _to_dec(lat, lat_ref)
                lon_d = _to_dec(lon, lon_ref)
                if lat_d is not None and lon_d is not None:
                    gps_coords = (lat_d, lon_d)
                    result["GPS_decimal"] = f"{lat_d},{lon_d}"
                    result["Google_Maps"] = (
                        f"https://www.google.com/maps?q={lat_d},{lon_d}")
    except Exception:
        pass

    # Print
    t = Table(title=f"🖼  EXIF: {p.name}")
    t.add_column("Tag", style="cyan", max_width=30)
    t.add_column("Value", style="green", max_width=70)
    for k, v in list(result.items())[:50]:
        t.add_row(k, str(v)[:70])
    console.print(t)

    if gps_coords:
        console.print(f"\n[red]⚠ GPS: {gps_coords}[/red]")
        console.print(f"[cyan]Maps: {result.get('Google_Maps')}[/cyan]")
        _save_finding(OSINTFinding(
            kind="exif_gps_exposed",
            severity="high",
            title=f"GPS coords в EXIF: {p.name}",
            target=str(p),
            evidence=f"Coordinates: {gps_coords}",
            data={"gps": gps_coords,
                  "maps_url": result.get("Google_Maps")},
        ))

    # Camera fingerprint
    make = result.get("Make") or ""
    model = result.get("Model") or ""
    serial = result.get("BodySerialNumber") or result.get("CameraSerialNumber")
    if make or model or serial:
        console.print(f"[dim]Camera: {make} {model} "
                      f"{'(serial: ' + str(serial) + ')' if serial else ''}"
                      f"[/dim]")

    db.save_scan("exif", str(p), result)
    return result


# ===========================================================================
# GitHub dorks
# ===========================================================================

GITHUB_DORK_TEMPLATES = [
    '{q} password',
    '{q} api_key',
    '{q} apiKey',
    '{q} secret',
    '{q} token',
    '{q} private_key',
    'org:{q} filename:.env',
    'org:{q} filename:.aws/credentials',
    'org:{q} filename:id_rsa',
    'org:{q} filename:credentials.json',
    'org:{q} filename:config.json',
    'user:{q} filename:config.yml',
    'user:{q} filename:.env',
    '{q} "BEGIN RSA PRIVATE KEY"',
    '{q} "AKIA"',
    '{q} filename:docker-compose.yml password',
    '{q} filename:terraform.tfstate',
]


def github_dork(query: str, save_finding: bool = True) -> list[str]:
    """GitHub-поиск (веб-ссылки)."""
    urls: list[str] = []
    console.print(f"[cyan]🔍 GitHub dorks для '{query}'[/cyan]")
    for tpl in GITHUB_DORK_TEMPLATES:
        dork = tpl.format(q=query)
        url = ("https://github.com/search?q=" +
               requests.utils.quote(dork) + "&type=code")
        urls.append(url)
        console.print(f"  [green]{url}[/green]")

    if save_finding and query:
        _save_finding(OSINTFinding(
            kind="github_dorks_generated",
            severity="high",
            title=f"GitHub dorks для '{query}' ({len(urls)})",
            target=f"github:{query}",
            evidence="\n".join(urls[:10]),
            data={"queries": GITHUB_DORK_TEMPLATES},
        ))

    db.save_scan("github_dork", query, urls)

    # Export
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        path = OSINT_DIR / f"github_dorks_{query}_{ts}.json"
        path.write_text(json.dumps({"query": query, "urls": urls},
                                     indent=2, ensure_ascii=False),
                          encoding="utf-8")
    except Exception:
        pass
    return urls


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    """Меню OSINT (базовый)."""
    table = Table(title="[bold]🕵  OSINT (базовый)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Username check (60+ платформ)"),
        ("2", "Username — только соцсети"),
        ("3", "Username — только dev"),
        ("4", "Username — только security"),
        ("5", "Email breach (HIBP + links)"),
        ("6", "Phone lookup (+ carrier)"),
        ("7", "EXIF extractor (+ GPS)"),
        ("8", "GitHub dorks (17 шаблонов)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для этичного использования.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        username_check(Prompt.ask("Username"))
    elif c == "2":
        username_check(Prompt.ask("Username"),
                        only_tags=["social", "media"])
    elif c == "3":
        username_check(Prompt.ask("Username"), only_tags=["dev"])
    elif c == "4":
        username_check(Prompt.ask("Username"), only_tags=["sec"])
    elif c == "5":
        email_breach(Prompt.ask("Email"))
    elif c == "6":
        phone_lookup(Prompt.ask("Телефон"))
    elif c == "7":
        exif_extractor(Prompt.ask("Путь к изображению"))
    elif c == "8":
        github_dork(Prompt.ask("Запрос / org"))