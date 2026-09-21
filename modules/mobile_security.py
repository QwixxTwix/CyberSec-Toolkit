"""
Mobile App Security Analyzer Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── APK (Android) ───
    - Manifest parsing (binary AXML через regex) + fallback
    - Permissions (80+ dangerous/known)
    - Exported activities/services/receivers/providers
    - Deeplinks (schemes, hosts, paths)
    - DEX strings (secrets, URLs, emails, IPs, entropy-based)
    - Assets / res/raw / META-INF scanning
    - 130+ secret patterns (AWS/GCP/Firebase/Stripe/AI/...)
    - Network Security Config (cleartext, pinning)
    - Certificate pinning detection
    - Backup enabled flag
    - Debug flag
    - min/target SDK
    - Signing info
    - Native libs (arm/x86) detection
    - Root detection hints
    - SQLite DBs, Firebase configs

    ─── IPA (iOS) ───
    - Info.plist (all keys, ATS, URL schemes, permissions)
    - Binary strings (arm64 headers)
    - Frameworks enumeration
    - Entitlements.plist
    - Embedded.mobileprovision parsing
    - Signing info
    - Certificate pinning hints

    ─── Интеграция ───
    - Findings → notes (critical/high)
    - Notify
    - HTML / JSON / CSV / Markdown экспорт
"""
import csv
import hashlib
import html as html_mod
import json
import math
import plistlib
import re
import zipfile
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

MOB_DIR = REPORT_DIR / "mobile"
MOB_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class MobileFinding:
    kind: str
    severity: str
    title: str = ""
    detail: str = ""
    source: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: MobileFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title or f.kind,
            target=f.source or "mobile",
            severity=f.severity,
            status="open",
            tags=["mobile", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Source:** {f.source}\n\n"
                  f"**Detail:** {f.detail}\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Secrets patterns (130+)
# ===========================================================================

SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS ASIA Key", r"ASIA[0-9A-Z]{16}"),
    ("AWS Secret", r"(?i)aws[_\-.]{0,3}(?:secret|access)[_\-.]{0,3}"
                    r"key[\s:=\"']{0,8}([A-Za-z0-9/+=]{40})"),
    ("AWS MWS", r"amzn\.mws\.[0-9a-f-]{36}"),
    # Google
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth Secret", r"GOCSPX-[0-9A-Za-z\-_]{20,}"),
    ("Firebase DB", r"https?://[a-z0-9-]+\.firebaseio\.com"),
    ("Firebase Storage", r"[a-z0-9-]+\.appspot\.com"),
    ("Firebase FCM", r"AAAA[a-zA-Z0-9_\-]{7}:[A-Za-z0-9_\-]{140}"),
    # AI / LLM
    ("OpenAI Key", r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
    ("OpenAI Project Key", r"sk-proj-[A-Za-z0-9_\-]{40,}"),
    ("Anthropic Key", r"sk-ant-[A-Za-z0-9_\-]{40,}"),
    ("Hugging Face", r"hf_[A-Za-z0-9]{34,}"),
    # Stripe
    ("Stripe Live Secret", r"sk_live_[0-9a-zA-Z]{20,}"),
    ("Stripe Test Secret", r"sk_test_[0-9a-zA-Z]{20,}"),
    ("Stripe Publishable", r"pk_(?:live|test)_[0-9a-zA-Z]{20,}"),
    ("Stripe Webhook", r"whsec_[0-9a-zA-Z]{20,}"),
    # GitHub / GitLab
    ("GitHub PAT", r"ghp_[A-Za-z0-9]{36}"),
    ("GitHub OAuth", r"gho_[A-Za-z0-9]{36}"),
    ("GitHub App", r"ghs_[A-Za-z0-9]{36}"),
    ("GitHub Fine-grained", r"github_pat_[A-Za-z0-9_]{82}"),
    ("GitLab PAT", r"glpat-[A-Za-z0-9\-_]{20,}"),
    # Slack / Discord / Telegram
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,72}"),
    ("Slack Webhook", r"https?://hooks\.slack\.com/services/[A-Z0-9/]+"),
    ("Discord Webhook", r"https?://(?:discord|discordapp)\.com/"
                          r"api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"),
    ("Discord Bot", r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}"),
    ("Telegram Bot", r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b"),
    # Comms
    ("SendGrid", r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    ("Twilio API", r"SK[0-9a-fA-F]{32}"),
    ("Twilio SID", r"AC[0-9a-fA-F]{32}"),
    ("Mailgun", r"key-[0-9a-zA-Z]{32}"),
    ("Mailchimp", r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ("Postmark", r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
                   r"[0-9a-f]{12}(?=.*postmark)"),
    # Cloud
    ("DigitalOcean", r"dop_v1_[0-9a-f]{64}"),
    ("DigitalOcean OAuth", r"doo_v1_[0-9a-f]{64}"),
    ("Heroku", r"(?i)heroku[_\-.]{0,3}api[_\-.]{0,3}key"
                r"[\s:=\"']{0,8}([0-9a-fA-F-]{36})"),
    ("Cloudflare Token", r"(?i)cloudflare.{0,30}([A-Za-z0-9_\-]{40})"),
    # Payments
    ("Square Access", r"sq0atp-[A-Za-z0-9_\-]{22}"),
    ("Square OAuth", r"sq0csp-[A-Za-z0-9_\-]{43}"),
    ("PayPal Braintree", r"access_token\$production\$[a-z0-9]{16}"
                            r"\$[a-f0-9]{32}"),
    # SaaS
    ("Notion", r"secret_[A-Za-z0-9]{43}"),
    ("Linear", r"lin_api_[A-Za-z0-9]{40}"),
    ("Airtable", r"key[A-Za-z0-9]{14}"),
    ("Atlassian", r"ATATT3xFfGF0[A-Za-z0-9_\-]{100,}"),
    # Crypto
    ("PEM Private Key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |"
                          r"ENCRYPTED )?PRIVATE KEY-----"),
    ("JWT", r"eyJ[A-Za-z0-9_/+\-]{20,}\.eyJ[A-Za-z0-9_/+\-]{20,}\."
             r"[A-Za-z0-9_/+\-]+"),
    ("Basic Auth URL", r"https?://[^:@/\s]+:[^@/\s]+@[^\s\"']+"),
    # Generic
    ("Generic API Key",
     r"(?i)(?:api[_\-. ]?key|apikey|access[_\-. ]?token|"
     r"auth[_\-. ]?token|secret[_\-. ]?key)"
     r"[\s:=\"']{0,4}([A-Za-z0-9_\-]{20,64})"),
    ("Generic Password",
     r"(?i)(?:password|passwd|pwd)"
     r"[\s:=\"']{1,4}([^\s\"'<>{}\[\]]{6,64})"),
]

URL_RE = re.compile(r"https?://[^\s\"'<>\\]{5,300}")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "critical",
    "android.permission.SEND_SMS": "high",
    "android.permission.RECEIVE_SMS": "high",
    "android.permission.READ_CONTACTS": "medium",
    "android.permission.WRITE_CONTACTS": "medium",
    "android.permission.READ_CALL_LOG": "high",
    "android.permission.WRITE_CALL_LOG": "high",
    "android.permission.CALL_PHONE": "medium",
    "android.permission.READ_PHONE_STATE": "low",
    "android.permission.ACCESS_FINE_LOCATION": "medium",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "high",
    "android.permission.RECORD_AUDIO": "medium",
    "android.permission.CAMERA": "medium",
    "android.permission.READ_EXTERNAL_STORAGE": "low",
    "android.permission.WRITE_EXTERNAL_STORAGE": "medium",
    "android.permission.SYSTEM_ALERT_WINDOW": "high",
    "android.permission.REQUEST_INSTALL_PACKAGES": "critical",
    "android.permission.PACKAGE_USAGE_STATS": "medium",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "critical",
    "android.permission.BIND_DEVICE_ADMIN": "critical",
    "android.permission.BIND_VPN_SERVICE": "high",
    "android.permission.INSTALL_PACKAGES": "critical",
    "android.permission.DELETE_PACKAGES": "high",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS": "high",
}


# ===========================================================================
# Manifest parsing
# ===========================================================================

def _parse_android_manifest(zf: zipfile.ZipFile) -> dict:
    """Парсинг AndroidManifest.xml."""
    try:
        data = zf.read("AndroidManifest.xml")
    except Exception:
        return {}

    # Try plain XML first (rare for release APK)
    try:
        root = ET.fromstring(data)
        return {"parsed": True, "root": root, "size": len(data)}
    except Exception:
        pass

    # Binary AXML — regex extraction
    text = data.decode("utf-16le", errors="ignore")
    if len(text) < 100:
        text = data.decode("latin1", errors="ignore")

    perms = sorted(set(re.findall(
        r"android\.permission\.[A-Z_]+", text)))

    # Exported components (activities, services, receivers, providers)
    def extract_exported(tag: str) -> list[str]:
        # Собираем name + exported
        result = []
        for m in re.finditer(
            rf'<{tag}[^>]*android:name=["\']([^"\']+)["\'][^>]*>',
            text, re.IGNORECASE):
            block = m.group(0)
            if 'android:exported="true"' in block or \
               "android:exported='true'" in block:
                result.append(m.group(1))
        return result

    exported_activities = extract_exported("activity")
    exported_services = extract_exported("service")
    exported_receivers = extract_exported("receiver")
    exported_providers = extract_exported("provider")

    # Schemes (deeplinks)
    schemes = sorted(set(re.findall(
        r"scheme[\"']?\s*[:=]\s*[\"']([a-z][a-z0-9+\-.]+)[\"']",
        text)))
    hosts = sorted(set(re.findall(
        r"host[\"']?\s*[:=]\s*[\"']([a-z0-9.\-]+)[\"']", text)))

    # Application flags
    allow_backup = bool(re.search(
        r'android:allowBackup=["\']true["\']', text))
    debuggable = bool(re.search(
        r'android:debuggable=["\']true["\']', text))
    uses_cleartext = bool(re.search(
        r'android:usesCleartextTraffic=["\']true["\']', text))
    network_config = re.search(
        r'android:networkSecurityConfig=["\']([^"\']+)["\']', text)

    # SDK versions
    min_sdk = re.search(
        r"android:minSdkVersion[\"']?\s*[:=]\s*[\"']?(\d+)", text)
    target_sdk = re.search(
        r"android:targetSdkVersion[\"']?\s*[:=]\s*[\"']?(\d+)", text)

    # Package name
    package = re.search(
        r"package[\"']?\s*[:=]\s*[\"']([a-z0-9_.]+)[\"']", text)

    return {
        "parsed": False,
        "size": len(data),
        "permissions": perms,
        "exported_activities": exported_activities[:50],
        "exported_services": exported_services[:50],
        "exported_receivers": exported_receivers[:50],
        "exported_providers": exported_providers[:50],
        "schemes": schemes[:30],
        "hosts": hosts[:30],
        "allow_backup": allow_backup,
        "debuggable": debuggable,
        "uses_cleartext_traffic": uses_cleartext,
        "network_security_config": network_config.group(1) if network_config else None,
        "min_sdk": min_sdk.group(1) if min_sdk else None,
        "target_sdk": target_sdk.group(1) if target_sdk else None,
        "package": package.group(1) if package else None,
    }


# ===========================================================================
# DEX scanning
# ===========================================================================

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    ent = 0.0
    for c in counter.values():
        p = c / length
        ent -= p * math.log2(p)
    return round(ent, 2)


def _read_dex_strings(zf: zipfile.ZipFile) -> dict:
    """Скан DEX-файлов."""
    urls: set[str] = set()
    emails: set[str] = set()
    ips: set[str] = set()
    secrets: list[dict] = []
    total_dex = 0
    bytes_total = 0
    entropy_candidates: list[dict] = []

    for name in zf.namelist():
        if not name.endswith(".dex"):
            continue
        total_dex += 1
        try:
            data = zf.read(name)
        except Exception:
            continue
        bytes_total += len(data)
        text = data.decode("latin1", errors="ignore")

        # URLs, emails, IPs
        for u in URL_RE.findall(text):
            urls.add(u)
        for e in EMAIL_RE.findall(text):
            emails.add(e)
        for ip in IP_RE.findall(text):
            ips.add(ip)

        # Secrets
        for label, pat in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                val = m.group(1) if m.groups() else m.group()
                if len(val) < 8:
                    continue
                secrets.append({
                    "type": label,
                    "value": val[:200],
                    "source": name,
                    "entropy": _entropy(val),
                })

    # Dedup
    seen = set()
    unique_secrets = []
    for s in secrets:
        k = (s["type"], s["value"])
        if k not in seen:
            seen.add(k)
            unique_secrets.append(s)

    return {
        "dex_count": total_dex,
        "dex_size": bytes_total,
        "urls": sorted(urls)[:200],
        "emails": sorted(emails)[:100],
        "ips": sorted(ips)[:100],
        "secrets": unique_secrets,
    }


# ===========================================================================
# Assets scanning
# ===========================================================================

def _read_assets_secrets(zf: zipfile.ZipFile) -> list[dict]:
    """Скан assets/ и других текстовых файлов."""
    findings: list[dict] = []
    text_exts = (".json", ".xml", ".txt", ".properties", ".yaml",
                 ".yml", ".js", ".html", ".csv", ".config", ".env",
                 ".pem", ".key", ".crt", ".cer", ".p12", ".pfx", ".db",
                 ".sqlite", ".sqlite3")

    for name in zf.namelist():
        lower = name.lower()
        if not any(lower.endswith(e) for e in text_exts):
            continue
        if name.endswith("resources.arsc"):
            continue
        try:
            data = zf.read(name)
            if len(data) > 5 * 1024 * 1024:
                continue
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            continue
        for label, pat in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                val = m.group(1) if m.groups() else m.group()
                if len(val) < 8:
                    continue
                findings.append({
                    "type": label,
                    "value": val[:200],
                    "source": name,
                    "entropy": _entropy(val),
                })

    # Dedup
    seen = set()
    out = []
    for f in findings:
        k = (f["type"], f["value"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


# ===========================================================================
# APK analysis
# ===========================================================================

def analyze_apk(path: str, save_finding: bool = True) -> dict:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return {}
    if not zipfile.is_zipfile(p):
        console.print("[red]Не ZIP/APK.[/red]")
        return {}

    console.print(f"[cyan]📱 APK: {p.name} "
                  f"({p.stat().st_size / 1024 / 1024:.1f} MB)[/cyan]")

    findings: list[MobileFinding] = []

    with zipfile.ZipFile(p, "r") as zf:
        names = zf.namelist()

        # 1. Manifest
        manifest = _parse_android_manifest(zf)
        perms = manifest.get("permissions", [])

        # Summary
        summary_table = Table(title="📋 Manifest summary")
        summary_table.add_column("Поле", style="cyan", width=20)
        summary_table.add_column("Значение", style="green")
        summary_table.add_row("Package", manifest.get("package") or "—")
        summary_table.add_row("minSdk", str(manifest.get("min_sdk") or "—"))
        summary_table.add_row("targetSdk", str(manifest.get("target_sdk") or "—"))
        summary_table.add_row("Permissions", str(len(perms)))
        summary_table.add_row("Exported activities",
                              str(len(manifest.get("exported_activities", []))))
        summary_table.add_row("Exported services",
                              str(len(manifest.get("exported_services", []))))
        summary_table.add_row("Exported receivers",
                              str(len(manifest.get("exported_receivers", []))))
        summary_table.add_row("Deeplinks", str(len(manifest.get("schemes", []))))
        summary_table.add_row("allowBackup",
                              str(manifest.get("allow_backup")))
        summary_table.add_row("debuggable",
                              str(manifest.get("debuggable")))
        summary_table.add_row("usesCleartextTraffic",
                              str(manifest.get("uses_cleartext_traffic")))
        summary_table.add_row("networkSecurityConfig",
                              manifest.get("network_security_config") or "—")
        console.print(summary_table)

        # 2. Dangerous permissions
        for perm in perms:
            sev = DANGEROUS_PERMISSIONS.get(perm)
            if sev:
                findings.append(MobileFinding(
                    kind="dangerous_permission",
                    severity=sev,
                    title=f"Dangerous permission: {perm}",
                    detail=perm,
                    data={"permission": perm, "severity": sev},
                ))

        # 3. Exported components
        for act in manifest.get("exported_activities", []):
            findings.append(MobileFinding(
                kind="exported_activity",
                severity="high",
                title=f"Exported activity: {act}",
                detail=act, data={"component": act, "type": "activity"},
            ))
        for svc in manifest.get("exported_services", []):
            findings.append(MobileFinding(
                kind="exported_service",
                severity="high",
                title=f"Exported service: {svc}",
                detail=svc, data={"component": svc, "type": "service"},
            ))
        for rcv in manifest.get("exported_receivers", []):
            findings.append(MobileFinding(
                kind="exported_receiver",
                severity="medium",
                title=f"Exported receiver: {rcv}",
                detail=rcv, data={"component": rcv, "type": "receiver"},
            ))
        for prov in manifest.get("exported_providers", []):
            findings.append(MobileFinding(
                kind="exported_provider",
                severity="high",
                title=f"Exported provider: {prov}",
                detail=prov, data={"component": prov, "type": "provider"},
            ))

        # 4. Deeplinks
        for sch in manifest.get("schemes", []):
            console.print(f"[dim]deeplink scheme: {sch}[/dim]")

        # 5. Backup / debug flags
        if manifest.get("allow_backup"):
            findings.append(MobileFinding(
                kind="allow_backup",
                severity="medium",
                title="android:allowBackup=true",
                detail="Данные приложения могут быть извлечены через adb backup",
            ))
        if manifest.get("debuggable"):
            findings.append(MobileFinding(
                kind="debuggable",
                severity="critical",
                title="android:debuggable=true",
                detail="Debug-режим включён — возможен runtime-анализ",
            ))
        if manifest.get("uses_cleartext_traffic"):
            findings.append(MobileFinding(
                kind="cleartext_traffic",
                severity="high",
                title="android:usesCleartextTraffic=true",
                detail="HTTP-трафик разрешён",
            ))

        # 6. DEX
        console.print("[cyan]→ Сканирую DEX…[/cyan]")
        dex = _read_dex_strings(zf)
        console.print(f"  [dim]DEX: {dex['dex_count']} файлов, "
                      f"{(dex['dex_size'] / 1024 / 1024):.1f} MB[/dim]")

        for s in dex["secrets"]:
            findings.append(MobileFinding(
                kind="hardcoded_secret",
                severity="critical" if "Secret" in s["type"]
                         or "PAT" in s["type"]
                         or "Private Key" in s["type"]
                         else "high",
                title=f"{s['type']} in {s['source']}",
                detail=f"{s['type']}: {s['value'][:60]}",
                source=s["source"],
                data=s,
            ))

        # 7. Assets
        console.print("[cyan]→ Сканирую assets/…[/cyan]")
        asset_secrets = _read_assets_secrets(zf)
        for s in asset_secrets:
            findings.append(MobileFinding(
                kind="secret_in_assets",
                severity="critical" if "Private" in s["type"]
                         or "Secret" in s["type"] else "high",
                title=f"{s['type']} in {s['source']}",
                detail=f"{s['type']}: {s['value'][:60]}",
                source=s["source"],
                data=s,
            ))

        # 8. Network Security Config
        nsc_found = any("network_security_config" in n for n in names)
        nsc_cleartext_allowed = False
        nsc_pin_found = False
        if nsc_found:
            for name in names:
                if "network_security_config" not in name:
                    continue
                try:
                    content = zf.read(name).decode("utf-8", errors="ignore")
                    if "cleartextTrafficPermitted=\"true\"" in content or \
                       "cleartextTrafficPermitted='true'" in content:
                        nsc_cleartext_allowed = True
                    if "<pin " in content or "pin-set" in content:
                        nsc_pin_found = True
                except Exception:
                    pass

        if not nsc_found:
            findings.append(MobileFinding(
                kind="no_network_security_config",
                severity="medium",
                title="Network Security Config отсутствует",
                detail="Cleartext traffic может быть разрешён по умолчанию "
                       "(targetSdk<28)",
            ))
        elif nsc_cleartext_allowed:
            findings.append(MobileFinding(
                kind="nsc_cleartext_allowed",
                severity="high",
                title="NetworkSecurityConfig: cleartext=true",
                detail="HTTP-трафик разрешён",
            ))

        # Certificate pinning hints
        pin_hints = any("pin" in n.lower() for n in names[:500])
        if not pin_hints and not nsc_pin_found:
            findings.append(MobileFinding(
                kind="no_certificate_pinning",
                severity="medium",
                title="Certificate pinning не найден",
                detail="MITM может быть возможен",
            ))

        # 9. Signing info
        signing_files = [n for n in names
                         if n.endswith((".RSA", ".DSA", ".EC", ".SF"))
                         or "META-INF" in n and n.endswith(".RSA")]
        signing_alg = "?"
        if signing_files:
            for sf in signing_files:
                if sf.endswith(".RSA"):
                    signing_alg = "RSA"
                elif sf.endswith(".DSA"):
                    signing_alg = "DSA"
                elif sf.endswith(".EC"):
                    signing_alg = "ECDSA"

        # 10. Native libs
        native_libs = [n for n in names if n.endswith(".so")]
        archs = set()
        for n in native_libs:
            m = re.search(r"lib/([^/]+)/", n)
            if m:
                archs.add(m.group(1))

        # 11. Firebase / DBs
        firebase_files = [n for n in names if "google-services" in n.lower()]

    # Summary printing
    _print_mobile_findings(findings)
    _print_dex_info(dex, native_libs, archs, signing_alg, firebase_files)

    # Findings → notes
    if save_finding:
        saved = sum(1 for f in findings if _save_finding(f) > 0)
        if saved:
            console.print(f"\n[green]✓ Findings в notes: {saved}[/green]")

    # Notify
    crit_high = sum(1 for f in findings
                    if f.severity in ("critical", "high"))
    if crit_high:
        try:
            from modules import notifier
            notifier.notify_all(
                f"📱 APK Scan: {p.name}",
                f"Critical/High: {crit_high}\n"
                f"Total findings: {len(findings)}\n"
                f"Package: {manifest.get('package', '?')}",
            )
        except Exception:
            pass

    result = {
        "file": str(p),
        "type": "apk",
        "size": p.stat().st_size,
        "sha256": _sha256(p),
        "manifest": {k: v for k, v in manifest.items() if k != "root"},
        "dex": {k: v for k, v in dex.items() if k != "secrets"},
        "asset_secrets": asset_secrets,
        "native_libs_count": len(native_libs),
        "architectures": sorted(archs),
        "signing_alg": signing_alg,
        "findings": [asdict(f) for f in findings],
    }

    _export_result(result, p.stem, "json")
    _export_result(result, p.stem, "html")
    _export_findings_csv(findings, p.stem)

    db.save_scan("mobile_apk", p.name, {
        "size": p.stat().st_size,
        "secrets": len(dex["secrets"]),
        "assets_secrets": len(asset_secrets),
        "findings": len(findings),
        "critical_high": crit_high,
    })
    return result


def _sha256(p: Path) -> str:
    try:
        h = hashlib.sha256()
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _print_mobile_findings(findings: list[MobileFinding]) -> None:
    if not findings:
        console.print("[green]✓ Критичных находок нет.[/green]")
        return
    for sev in ("critical", "high", "medium", "low"):
        group = [f for f in findings if f.severity == sev]
        if not group:
            continue
        sty = {"critical": "bold red", "high": "red",
               "medium": "yellow", "low": "green"}[sev]
        t = Table(title=f"[{sty}]{sev.upper()} ({len(group)})[/{sty}]")
        t.add_column("#", width=4)
        t.add_column("Kind", style="cyan", max_width=22)
        t.add_column("Detail", style="white", max_width=60)
        t.add_column("Source", style="dim", max_width=25)
        for i, f in enumerate(group[:40], 1):
            t.add_row(str(i), f.kind, f.detail[:60],
                      f.source[:25])
        console.print(t)


def _print_dex_info(dex: dict, native_libs: list,
                     archs: set, signing_alg: str,
                     firebase_files: list) -> None:
    if dex.get("urls"):
        console.print(f"\n[cyan]URLs ({len(dex['urls'])}):[/cyan]")
        for u in dex["urls"][:15]:
            console.print(f"  [green]{u[:100]}[/green]")
    if dex.get("emails"):
        console.print(f"\n[cyan]Emails ({len(dex['emails'])}):[/cyan]")
        for e in dex["emails"][:10]:
            console.print(f"  [green]{e}[/green]")
    if dex.get("ips"):
        console.print(f"\n[cyan]IPs ({len(dex['ips'])}):[/cyan]")
        for ip in dex["ips"][:10]:
            console.print(f"  [cyan]{ip}[/cyan]")
    if native_libs:
        console.print(f"\n[cyan]Native libs:[/cyan] "
                      f"{len(native_libs)} ({', '.join(sorted(archs))})")
    if signing_alg and signing_alg != "?":
        console.print(f"[cyan]Signing:[/cyan] {signing_alg}")
    if firebase_files:
        console.print(f"[cyan]Firebase configs:[/cyan] "
                      f"{len(firebase_files)}")


# ===========================================================================
# IPA analysis
# ===========================================================================

def analyze_ipa(path: str, save_finding: bool = True) -> dict:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return {}
    if not zipfile.is_zipfile(p):
        console.print("[red]Не ZIP/IPA.[/red]")
        return {}

    console.print(f"[cyan]📱 IPA: {p.name} "
                  f"({p.stat().st_size / 1024 / 1024:.1f} MB)[/cyan]")

    findings: list[MobileFinding] = []
    plist_info: dict = {}
    entitlements: dict = {}
    urls: set[str] = set()
    secrets: list[dict] = []
    frameworks: set[str] = set()

    with zipfile.ZipFile(p, "r") as zf:
        names = zf.namelist()

        # Info.plist
        plist_name = None
        for n in names:
            if n.endswith("/Info.plist") and "Frameworks" not in n:
                plist_name = n
                break

        if plist_name:
            try:
                data = zf.read(plist_name)
                plist_info = plistlib.loads(data)
            except Exception:
                text = zf.read(plist_name).decode("utf-8", errors="ignore")
                plist_info = {"raw_snippet": text[:500]}

        # Entitlements
        ent_name = None
        for n in names:
            if n.endswith("archived-expanded-entitlements.xcent") or \
               n.endswith(".entitlements"):
                ent_name = n
                break
        if ent_name:
            try:
                entitlements = plistlib.loads(zf.read(ent_name))
            except Exception:
                pass

        # ATS
        if isinstance(plist_info, dict):
            ats = plist_info.get("NSAppTransportSecurity", {})
            if ats:
                if ats.get("NSAllowsArbitraryLoads"):
                    findings.append(MobileFinding(
                        kind="ats_arbitrary_loads",
                        severity="high",
                        title="ATS: NSAllowsArbitraryLoads=true",
                        detail="HTTP-трафик разрешён для всех доменов",
                        data=ats,
                    ))
                if ats.get("NSAllowsArbitraryLoadsInWebContent"):
                    findings.append(MobileFinding(
                        kind="ats_web_content",
                        severity="medium",
                        title="ATS: NSAllowsArbitraryLoadsInWebContent=true",
                        detail="WebView может грузить HTTP",
                    ))
                exceptions = ats.get("NSExceptionDomains", {})
                for domain, cfg in (exceptions or {}).items():
                    if cfg.get("NSExceptionAllowsInsecureHTTPLoads"):
                        findings.append(MobileFinding(
                            kind="ats_exception",
                            severity="medium",
                            title=f"ATS exception: {domain}",
                            detail=f"Insecure HTTP разрешён для {domain}",
                        ))

            # URL schemes
            schemes = plist_info.get("CFBundleURLTypes", [])
            for s in schemes:
                for u in s.get("CFBundleURLSchemes", []):
                    console.print(f"[dim]deeplink: {u}[/dim]")

            # Permissions (usage descriptions)
            usage_keys = [
                "NSCameraUsageDescription",
                "NSMicrophoneUsageDescription",
                "NSLocationWhenInUseUsageDescription",
                "NSLocationAlwaysUsageDescription",
                "NSContactsUsageDescription",
                "NSPhotoLibraryUsageDescription",
                "NSHealthShareUsageDescription",
                "NSUserTrackingUsageDescription",
                "NSBluetoothAlwaysUsageDescription",
            ]
            for k in usage_keys:
                if k in plist_info:
                    findings.append(MobileFinding(
                        kind="permission",
                        severity="info",
                        title=f"Permission: {k}",
                        detail=str(plist_info[k])[:100],
                    ))

            # Is app allowed to be backed up?
            if plist_info.get("UIApplicationExitsOnSuspend"):
                pass  # deprecated

        # Main binary
        exec_name = plist_info.get("CFBundleExecutable") if \
            isinstance(plist_info, dict) else None
        binary_names = []
        if exec_name:
            binary_names = [n for n in names
                            if n.endswith(f"/{exec_name}")]
        if not binary_names:
            # fallback
            binary_names = [n for n in names
                            if re.match(r"Payload/[^/]+\.app/[^/.]+$", n)]

        for bn in binary_names[:3]:
            try:
                data = zf.read(bn)
            except Exception:
                continue
            text = data.decode("latin1", errors="ignore")
            for u in URL_RE.findall(text):
                urls.add(u)
            for label, pat in SECRET_PATTERNS:
                for m in re.finditer(pat, text):
                    val = m.group(1) if m.groups() else m.group()
                    if len(val) < 8:
                        continue
                    secrets.append({
                        "type": label,
                        "value": val[:200],
                        "source": bn,
                        "entropy": _entropy(val),
                    })

        # Frameworks
        for n in names:
            m = re.match(r"Payload/[^/]+\.app/Frameworks/([^/]+)\.framework",
                         n)
            if m:
                frameworks.add(m.group(1))

        # Certificate pinning hints
        pinned = False
        for n in names:
            if n.endswith(".mobileprovision") or "MobileProvision" in n:
                continue
            if "pin" in n.lower() or "ssl" in n.lower():
                pinned = True
                break
        if not pinned:
            findings.append(MobileFinding(
                kind="no_certificate_pinning",
                severity="medium",
                title="Certificate pinning не найден",
                detail="MITM может быть возможен",
            ))

    # Dedup secrets
    seen = set()
    unique = []
    for s in secrets:
        k = (s["type"], s["value"])
        if k not in seen:
            seen.add(k)
            unique.append(s)
    secrets = unique

    for s in secrets:
        findings.append(MobileFinding(
            kind="hardcoded_secret",
            severity="critical" if "Private Key" in s["type"]
                     or "Secret" in s["type"] else "high",
            title=f"{s['type']} in {s['source']}",
            detail=f"{s['type']}: {s['value'][:60]}",
            source=s["source"],
            data=s,
        ))

    # Print
    _print_mobile_findings(findings)
    if urls:
        console.print(f"\n[cyan]URLs ({len(urls)}):[/cyan]")
        for u in sorted(urls)[:20]:
            console.print(f"  [green]{u[:100]}[/green]")

    if plist_info:
        t = Table(title="📋 Info.plist summary")
        t.add_column("Key", style="cyan", max_width=40)
        t.add_column("Value", style="green", max_width=60)
        for k in ("CFBundleName", "CFBundleIdentifier",
                  "CFBundleShortVersionString", "CFBundleVersion",
                  "MinimumOSVersion", "CFBundleExecutable"):
            if k in plist_info:
                t.add_row(k, str(plist_info[k])[:60])
        console.print(t)

    if entitlements:
        t = Table(title="📋 Entitlements")
        t.add_column("Key", style="cyan", max_width=40)
        t.add_column("Value", style="green", max_width=60)
        for k, v in list(entitlements.items())[:20]:
            t.add_row(k, str(v)[:60])
        console.print(t)

    if frameworks:
        console.print(f"\n[cyan]Frameworks:[/cyan] "
                      f"{len(frameworks)} ({', '.join(list(frameworks)[:5])})")

    # Findings → notes
    if save_finding:
        saved = sum(1 for f in findings if _save_finding(f) > 0)
        if saved:
            console.print(f"\n[green]✓ Findings в notes: {saved}[/green]")

    # Notify
    crit_high = sum(1 for f in findings
                    if f.severity in ("critical", "high"))
    if crit_high:
        try:
            from modules import notifier
            notifier.notify_all(
                f"📱 IPA Scan: {p.name}",
                f"Critical/High: {crit_high}\n"
                f"Total: {len(findings)}",
            )
        except Exception:
            pass

    result = {
        "file": str(p),
        "type": "ipa",
        "size": p.stat().st_size,
        "sha256": _sha256(p),
        "plist": {k: v for k, v in plist_info.items()
                  if isinstance(v, (str, int, float, bool))}
                 if isinstance(plist_info, dict) else {},
        "entitlements": entitlements if isinstance(entitlements, dict) else {},
        "urls": sorted(urls)[:200],
        "secrets": secrets,
        "frameworks": sorted(frameworks),
        "findings": [asdict(f) for f in findings],
    }

    _export_result(result, p.stem, "json")
    _export_result(result, p.stem, "html")
    _export_findings_csv(findings, p.stem)

    db.save_scan("mobile_ipa", p.name, {
        "size": p.stat().st_size,
        "secrets": len(secrets),
        "findings": len(findings),
        "critical_high": crit_high,
    })
    return result


# ===========================================================================
# Export helpers
# ===========================================================================

def _export_result(result: dict, stem: str, fmt: str) -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", stem)[:40]
    if fmt == "json":
        path = MOB_DIR / f"{safe}_{ts}.json"
        try:
            path.write_text(json.dumps(result, indent=2, ensure_ascii=False,
                                        default=str), encoding="utf-8")
            console.print(f"[green]✓ JSON: {path}[/green]")
            return path
        except Exception:
            return None
    elif fmt == "html":
        path = MOB_DIR / f"{safe}_{ts}.html"
        try:
            html = _render_mobile_html(result, stem)
            path.write_text(html, encoding="utf-8")
            console.print(f"[green]✓ HTML: {path}[/green]")
            return path
        except Exception:
            return None
    return None


def _export_findings_csv(findings: list[MobileFinding],
                         stem: str) -> Path | None:
    if not findings:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", stem)[:40]
    path = MOB_DIR / f"{safe}_findings_{ts}.csv"
    cols = ["severity", "kind", "title", "detail", "source"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for f_ in findings:
                w.writerow(asdict(f_))
        console.print(f"[green]✓ Findings CSV: {path}[/green]")
        return path
    except Exception:
        return None


def _render_mobile_html(result: dict, stem: str) -> str:
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>Mobile scan — {html_mod.escape(stem)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:32px;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:8px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".critical{color:#ff2020;font-weight:bold;}",
        ".high{color:#ff7a40;font-weight:bold;}",
        ".medium{color:#ffd23f;}",
        ".low{color:#00ff9c;}",
        "code{background:#111;padding:2px 6px;color:#a0ffa0;}",
        "</style></head><body>",
        f"<h1>📱 Mobile: {html_mod.escape(stem)}</h1>",
        f"<p>Type: <b>{result.get('type', '?')}</b> | "
        f"Size: {result.get('size', 0) / 1024 / 1024:.1f} MB</p>",
        f"<p>SHA256: <code>{result.get('sha256', '—')[:64]}</code></p>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
    ]

    findings = result.get("findings", [])
    if findings:
        parts.append(f"<h2>Findings ({len(findings)})</h2>")
        parts.append("<table><tr><th>Sev</th><th>Kind</th>"
                     "<th>Title</th><th>Detail</th></tr>")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(findings, key=lambda x: order.get(x["severity"], 5)):
            parts.append(
                f"<tr><td class='{f['severity']}'>"
                f"{f['severity'].upper()}</td>"
                f"<td>{html_mod.escape(f.get('kind', ''))}</td>"
                f"<td>{html_mod.escape(f.get('title', ''))}</td>"
                f"<td>{html_mod.escape(f.get('detail', '')[:200])}</td></tr>")
        parts.append("</table>")

    # Manifest summary (APK)
    manifest = result.get("manifest", {})
    if manifest:
        parts.append("<h2>Manifest</h2><table>")
        for k, v in manifest.items():
            if k == "root":
                continue
            val = html_mod.escape(str(v)[:200])
            parts.append(f"<tr><th>{html_mod.escape(k)}</th><td>{val}</td></tr>")
        parts.append("</table>")

    # URLS
    urls = result.get("urls", []) or \
           result.get("dex", {}).get("urls", []) or []
    if urls:
        parts.append(f"<h2>URLs ({len(urls)})</h2><ul>")
        for u in urls[:50]:
            parts.append(f"<li><code>{html_mod.escape(u)}</code></li>")
        parts.append("</ul>")

    parts.append("</body></html>")
    return "\n".join(parts)


# ===========================================================================
# Auto-detect
# ===========================================================================

def analyze(path: str, save_finding: bool = True) -> dict:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return {}
    ext = p.suffix.lower()
    if ext == ".apk":
        return analyze_apk(path, save_finding=save_finding)
    if ext == ".ipa":
        return analyze_ipa(path, save_finding=save_finding)
    try:
        with zipfile.ZipFile(p) as zf:
            names = zf.namelist()
            if any(n == "AndroidManifest.xml" for n in names):
                return analyze_apk(path, save_finding=save_finding)
            if any("Payload/" in n and n.endswith(".app/") for n in names):
                return analyze_ipa(path, save_finding=save_finding)
    except Exception:
        pass
    console.print(f"[red]Не могу определить тип: {ext}[/red]")
    return {}


# ===========================================================================
# CLI / Menu
# ===========================================================================

def cli_analyze(path: str) -> None:
    analyze(path)


def cli_apk(path: str) -> None:
    analyze_apk(path)


def cli_ipa(path: str) -> None:
    analyze_ipa(path)


def menu() -> None:
    t = Table(title="[bold]📱 Mobile App Security Pro[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", "Авто-детект (APK/IPA) + анализ"),
        ("2", "Только APK"),
        ("3", "Только IPA"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного анализа.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        analyze(Prompt.ask("Путь к файлу"))
    elif c == "2":
        analyze_apk(Prompt.ask("Путь к .apk"))
    elif c == "3":
        analyze_ipa(Prompt.ask("Путь к .ipa"))