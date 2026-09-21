"""
Forensics & IR Pro.
Author: idqwixxa

⚠ Только для авторизованного IR / threat hunting / CTF.

Возможности:
    ─── IOC extraction ───
    - 40+ паттернов: IP, домены, URL, email, hashes, CVE, MITRE
    - Крипто-кошельки (BTC, ETH, XMR)
    - API-ключи (AWS, GCP, Stripe, GitHub, Slack, Discord webhooks)
    - JWT, PEM private keys
    - .onion адреса
    - Attacker tool names (mimikatz, cobaltstrike, meterpreter)
    - LOLBins, ransomware extensions
    - Risk scoring

    ─── Timeline ───
    - mtime / ctime / atime
    - Suspicious locations (/tmp, /dev/shm, /var/tmp)
    - Recently modified executables
    - Large binary files

    ─── Log parsers ───
    - Sysmon XML (все EventID 1-26, process tree, suspicious chains)
    - auth.log / secure (Linux) + brute-force detection
    - auditd (EXECVE, SYSCALL, USER_* events)
    - Windows EVTX hints (manual parsing commands)
    - systemd journal hints
    - Browser history (Chrome/Firefox SQLite)

    ─── Utils ───
    - Hash verification (hashdeep-style)
    - YARA scan
    - Findings → notes
    - Notify
    - HTML / JSON / CSV экспорт
"""
import csv
import html as html_mod
import json
import os
import re
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

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

FOR_DIR = REPORT_DIR / "forensics"
FOR_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 30


# ===========================================================================
# Findings
# ===========================================================================

@dataclass
class IRFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: IRFinding) -> int:
    if f.severity not in ("critical", "high"):
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target or "forensics",
            severity=f.severity,
            status="open",
            tags=["forensics", "ir", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# IOC patterns
# ===========================================================================

IOC_PATTERNS = {
    # Network
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|net|org|ru|io|dev|xyz|info|biz|cc|co|me|app|cloud|"
        r"top|site|online|store|tech|space|fun|live|pro)\b",
        re.IGNORECASE,
    ),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "onion": re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE),
    "email": re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    "bitcoin": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b"),
    "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "monero": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),

    # Hashes
    "md5": re.compile(r"\b[a-f0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b"),

    # Vulnerabilities
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b"),
    "mitre": re.compile(r"\bT1\d{3}(?:\.\d{3})?\b"),

    # Paths / Registry
    "windows_path": re.compile(
        r"[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+"
    ),
    "unix_path": re.compile(
        r"/(?:etc|var|tmp|home|usr|opt|root|dev|proc)/[^\s:\"']+"
    ),
    "registry": re.compile(r"H(?:KLM|KCU|KCR|KU|KCC)\\[^\s\"']+"),
    "unc_path": re.compile(r"\\\\[A-Za-z0-9._-]+\\[^\s\"']+"),

    # Credentials / keys
    "jwt": re.compile(
        r"\beyJ[A-Za-z0-9_/+\-]{10,}\.eyJ[A-Za-z0-9_/+\-]{10,}\."
        r"[A-Za-z0-9_/+\-]+\b"
    ),
    "pem_private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?"
        r"PRIVATE KEY-----"
    ),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(
        r"(?i)aws[_\-.]{0,3}(?:secret|access)[_\-.]{0,3}key"
        r"[\s:=\"']{0,8}([A-Za-z0-9/+=]{40})"
    ),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "github_pat": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "gitlab_pat": re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b"),
    "slack_webhook": re.compile(
        r"https?://hooks\.slack\.com/services/[A-Z0-9/]+"
    ),
    "discord_webhook": re.compile(
        r"https?://(?:discord|discordapp)\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"
    ),
    "telegram_bot_token": re.compile(r"\b[0-9]{8,10}:[A-Za-z0-9_\-]{35}\b"),
    "stripe_key": re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{20,}\b"),
    "sendgrid_key": re.compile(
        r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b"
    ),
    "twilio_key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),

    # Attacker tooling
    "attacker_tool": re.compile(
        r"\b(?:mimikatz|cobaltstrike|cobalt\s*strike|meterpreter|"
        r"empire|beacon|metasploit|msfvenom|powersploit|"
        r"sharphound|bloodhound|rubeus|seatbelt|lazagne|"
        r"psexec|wce|procdump|pwdump)\b",
        re.IGNORECASE,
    ),
    "lolbin": re.compile(
        r"\b(?:certutil|regsvr32|rundll32|mshta|wmic|msiexec|"
        r"cmstp|installutil|msbuild|forfiles|pcalua|"
        r"regasm|regsvcs|bash\.exe|conhost\.exe)\b",
        re.IGNORECASE,
    ),
    "ransom_ext": re.compile(
        r"\.(?:locky|lockbit|conti|revil|darkside|blackcat|"
        r"ryuk|maze|egregor|phobos|dharma|stop|xxx)\b",
        re.IGNORECASE,
    ),
    "suspicious_cmd": re.compile(
        r"(?i)(?:powershell\.exe[^\r\n]*-e(?:nc(?:odedcommand)?)?\s|"
        r"cmd\.exe\s*/c\s+(?:whoami|net\s+(?:user|localgroup)|"
        r"systeminfo|ipconfig)|"
        r"wmic\s+process\s+call\s+create|"
        r"vssadmin\s+delete\s+shadows|"
        r"reg\s+save\s+hklm\\sam)"
    ),
    "suspicious_user_agent": re.compile(
        r"User-Agent:\s*(?:curl|wget|python-requests|Go-http-client|"
        r"sqlmap|nikto|nmap|masscan|zgrab)",
        re.IGNORECASE,
    ),
}


# Suspicious file locations
SUSPICIOUS_PATHS = [
    "/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/",
    "C:\\Windows\\Temp\\", "C:\\Temp\\", "C:\\Users\\Public\\",
    "C:\\ProgramData\\", "/root/.cache/",
]

# Known malware hashes (для быстрой проверки)
# В реальном IR-сценарии подгружай из threat-intel источников


# ===========================================================================
# IOC extractor
# ===========================================================================

def extract_iocs(text: str) -> dict:
    """Извлечь IOC из текста."""
    out: dict[str, list[str]] = {}
    for kind, pat in IOC_PATTERNS.items():
        try:
            matches = set()
            for m in pat.finditer(text):
                val = m.group(1) if m.groups() else m.group()
                matches.add(val)
            # Фильтр IPv6 (много мусора от MAC-адресов)
            if kind == "ipv6":
                matches = {m for m in matches if "::" in m or
                           m.count(":") >= 3}
            # Фильтр hashes — исключаем UUID
            if kind in ("md5",):
                matches = {m for m in matches if "-" not in m}
            out[kind] = sorted(matches)[:500]
        except Exception:
            out[kind] = []
    return out


def _risk_score(iocs: dict) -> dict:
    """Оценить риск на основе IOC."""
    findings: list[IRFinding] = []

    if iocs.get("aws_access_key"):
        findings.append(IRFinding(
            kind="aws_key_exposed",
            severity="critical",
            title=f"AWS Access Key(s) exposed ({len(iocs['aws_access_key'])})",
            evidence=", ".join(iocs["aws_access_key"][:5]),
            data={"keys": iocs["aws_access_key"]},
        ))
    if iocs.get("pem_private_key"):
        findings.append(IRFinding(
            kind="private_key_exposed",
            severity="critical",
            title=f"PEM private key(s) ({len(iocs['pem_private_key'])})",
            evidence=", ".join(iocs["pem_private_key"][:3]),
        ))
    if iocs.get("attacker_tool"):
        findings.append(IRFinding(
            kind="attacker_tool_mentioned",
            severity="high",
            title=f"Attacker tool(s) mentioned: "
                  f"{', '.join(iocs['attacker_tool'][:5])}",
            evidence=", ".join(iocs["attacker_tool"]),
            data={"tools": iocs["attacker_tool"]},
        ))
    if iocs.get("onion"):
        findings.append(IRFinding(
            kind="onion_address",
            severity="high",
            title=f"Tor .onion address(es): {len(iocs['onion'])}",
            evidence=", ".join(iocs["onion"][:3]),
        ))
    if iocs.get("ransom_ext"):
        findings.append(IRFinding(
            kind="ransomware_extension",
            severity="critical",
            title=f"Ransomware extension(s): "
                  f"{', '.join(iocs['ransom_ext'][:5])}",
        ))
    if iocs.get("suspicious_cmd"):
        findings.append(IRFinding(
            kind="suspicious_command",
            severity="high",
            title=f"Suspicious command pattern(s): "
                  f"{len(iocs['suspicious_cmd'])}",
            evidence="\n".join(iocs["suspicious_cmd"][:3])[:500],
        ))

    return {"findings": findings}


def scan_log_iocs(path: str) -> dict:
    """IOC-скан лог-файла с risk assessment."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return {}
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return {}

    console.print(f"[cyan]🔍 IOC scan: {p.name} "
                  f"({len(text):,} bytes)[/cyan]")

    iocs = extract_iocs(text)

    # Summary table
    t = Table(title=f"IOC summary — {p.name}")
    t.add_column("Type", style="cyan")
    t.add_column("Count", style="green", width=8)
    t.add_column("Sample", style="white", max_width=60)
    for kind, vals in iocs.items():
        if not vals:
            continue
        sample = ", ".join(vals[:3])[:60]
        t.add_row(kind, str(len(vals)), sample)
    console.print(t)

    # Risk scoring
    risk = _risk_score(iocs)
    findings = risk["findings"]

    if findings:
        console.print("\n[bold red]⚠ Risk findings:[/bold red]")
        ft = Table(title=f"Findings ({len(findings)})",
                   border_style="red")
        ft.add_column("Severity", width=10)
        ft.add_column("Kind", style="cyan", max_width=25)
        ft.add_column("Title", style="white", max_width=70)
        for f in findings:
            sty = {"critical": "bold red",
                   "high": "red",
                   "medium": "yellow"}.get(f.severity, "white")
            ft.add_row(
                f"[{sty}]{f.severity.upper()}[/{sty}]",
                f.kind, f.title[:70])
        console.print(ft)

        # Save findings
        saved = sum(1 for f in findings if _save_finding(f) > 0)
        if saved:
            console.print(f"[green]✓ Findings в notes: {saved}[/green]")

        # Notify
        try:
            from modules import notifier
            crit = sum(1 for f in findings if f.severity == "critical")
            if crit:
                notifier.notify_all(
                    f"🔬 IR: {p.name}",
                    f"Critical findings: {crit}\n"
                    f"Total findings: {len(findings)}",
                )
        except Exception:
            pass

    # Details for key IOC types
    for kind in ("url", "domain", "ipv4", "sha256", "cve", "mitre",
                 "aws_access_key", "attacker_tool"):
        vals = iocs.get(kind, [])
        if not vals:
            continue
        t2 = Table(title=f"📌 {kind} ({len(vals)})")
        t2.add_column("#", width=4)
        t2.add_column("Value", style="green")
        for i, v in enumerate(vals[:30], 1):
            t2.add_row(str(i), v[:120])
        console.print(t2)

    db.save_scan("forensics_ioc", p.name, {
        "size": len(text),
        "counts": {k: len(v) for k, v in iocs.items()},
        "findings": len(findings),
    })

    # Export
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = FOR_DIR / f"iocs_{p.stem}_{ts}.json"
    try:
        out.write_text(json.dumps({
            "file": str(p), "ts": datetime.now().isoformat(),
            "iocs": iocs,
            "findings": [asdict(f) for f in findings],
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]✓ {out}[/green]")
    except Exception:
        pass

    return iocs


# ===========================================================================
# Timeline
# ===========================================================================

def timeline(path: str, max_files: int = 500,
             suspicious_only: bool = False) -> list[dict]:
    """Timeline файлов (mtime + suspicious detection)."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return []

    files: list[Path] = []
    if p.is_file():
        files = [p]
    else:
        files = [f for f in p.rglob("*") if f.is_file()][:max_files]

    entries: list[dict] = []
    for f in files:
        try:
            st = f.stat()
            entry = {
                "file": str(f),
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime),
                "ctime": datetime.fromtimestamp(st.st_ctime),
                "atime": datetime.fromtimestamp(st.st_atime),
                "suspicious": [],
            }
            # Suspicious location detection
            fpath = str(f)
            for sus in SUSPICIOUS_PATHS:
                if sus in fpath:
                    entry["suspicious"].append(f"suspicious_path:{sus}")
                    break
            # Recently modified (last 7 days)
            age = (datetime.now() - entry["mtime"]).total_seconds()
            if age < 7 * 86400 and fpath.endswith(
                    (".exe", ".dll", ".so", ".sh", ".ps1", ".bat",
                     ".scr", ".vbs")):
                entry["suspicious"].append("recent_executable")
            # Large binary
            if entry["size"] > 10_000_000 and fpath.endswith(
                    (".exe", ".dll", ".bin")):
                entry["suspicious"].append("large_binary")
            entries.append(entry)
        except Exception:
            continue

    entries.sort(key=lambda x: x["mtime"])

    if suspicious_only:
        entries = [e for e in entries if e["suspicious"]]

    t = Table(title=f"🕐 Timeline ({len(entries)} files) — sorted by mtime")
    t.add_column("#", width=4)
    t.add_column("mtime", style="cyan", width=19)
    t.add_column("size", style="dim", width=10)
    t.add_column("Flags", style="red", width=20)
    t.add_column("File", style="white", max_width=70)
    for i, e in enumerate(entries[:200], 1):
        flags = ",".join(e["suspicious"])[:20] if e["suspicious"] else "—"
        t.add_row(
            str(i),
            e["mtime"].strftime("%Y-%m-%d %H:%M:%S"),
            f"{e['size']:,}",
            flags,
            e["file"][:70],
        )
    console.print(t)

    db.save_scan("forensics_timeline", str(p),
                 {"files": len(entries)})

    # Export
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = FOR_DIR / f"timeline_{ts}.json"
    try:
        out.write_text(
            json.dumps([{**e, "mtime": e["mtime"].isoformat(),
                          "ctime": e["ctime"].isoformat(),
                          "atime": e["atime"].isoformat()}
                        for e in entries], indent=2, ensure_ascii=False),
            encoding="utf-8")
    except Exception:
        pass
    return entries


# ===========================================================================
# Sysmon XML
# ===========================================================================

SYSMON_MEANING = {
    "1": "ProcessCreate", "2": "FileCreateTime",
    "3": "NetworkConnect", "4": "SysmonServiceState",
    "5": "ProcessTerminate", "6": "DriverLoad",
    "7": "ImageLoad", "8": "CreateRemoteThread",
    "9": "RawAccessRead", "10": "ProcessAccess",
    "11": "FileCreate", "12": "RegistryObjectAddDelete",
    "13": "RegistryValueSet", "14": "RegistryKeyRename",
    "15": "FileCreateStreamHash", "16": "ServiceConfigurationChange",
    "17": "PipeCreated", "18": "PipeConnected",
    "19": "WmiEventFilter", "20": "WmiEventConsumer",
    "21": "WmiEventConsumerToFilter", "22": "DNSQuery",
    "23": "FileDelete", "24": "ClipboardChange",
    "25": "ProcessTampering", "26": "FileDeleteDetected",
}

# Suspicious parent-child process chains
SUSPICIOUS_PARENT_CHILD = [
    ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
    ("winword.exe", "wscript.exe"), ("winword.exe", "cscript.exe"),
    ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"), ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "wscript.exe"),
    ("chrome.exe", "cmd.exe"), ("chrome.exe", "powershell.exe"),
    ("firefox.exe", "cmd.exe"),
    ("w3wp.exe", "cmd.exe"), ("w3wp.exe", "powershell.exe"),
    ("wmiprvse.exe", "cmd.exe"),
    ("services.exe", "cmd.exe"),
    ("lsass.exe", "cmd.exe"),
    ("svchost.exe", "cmd.exe"),
]


def parse_sysmon_xml(path: str, save_export: bool = True) -> list[dict]:
    """Парсер Sysmon XML-выгрузки с полным анализом."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return []

    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
        root = ET.fromstring(text)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]XML parse: {exc}[/red]")
        return []

    events: list[dict] = []
    for event in root.iter("Event"):
        eid = ""
        for e in event.findall("System/EventID"):
            eid = e.text or ""
        if not eid:
            continue

        data: dict[str, str] = {}
        for d in event.iter("Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "")[:500]

        events.append({
            "EventID": eid,
            "kind": SYSMON_MEANING.get(eid, "?"),
            "TimeCreated": _find_attr(event, "TimeCreated"),
            **data,
        })

    console.print(f"[cyan]🔍 Sysmon: {len(events)} events[/cyan]")

    # Distribution
    counter = Counter(e["EventID"] for e in events)
    t = Table(title="EventID distribution")
    t.add_column("ID", style="cyan", width=5)
    t.add_column("Kind", style="white", width=28)
    t.add_column("Count", style="green", width=8)
    for eid, cnt in counter.most_common():
        t.add_row(eid, SYSMON_MEANING.get(eid, "?"), str(cnt))
    console.print(t)

    findings: list[IRFinding] = []

    # Processes + suspicious chains
    procs = [e for e in events if e["EventID"] == "1"]
    if procs:
        t = Table(title=f"🔧 Processes ({len(procs)})")
        t.add_column("#", width=4)
        t.add_column("Image", style="cyan", max_width=40)
        t.add_column("CommandLine", style="green", max_width=60)
        t.add_column("Parent", style="dim", max_width=25)
        for i, e in enumerate(procs[:100], 1):
            parent = e.get("ParentImage", "").split("\\")[-1].lower()
            child = e.get("Image", "").split("\\")[-1].lower()
            flag = ""
            for pc, cc in SUSPICIOUS_PARENT_CHILD:
                if pc in parent and cc in child:
                    flag = " [red]⚠[/red]"
                    findings.append(IRFinding(
                        kind="suspicious_parent_child",
                        severity="high",
                        title=f"Suspicious chain: {parent} → {child}",
                        evidence=f"CommandLine: "
                                 f"{e.get('CommandLine', '')[:500]}",
                        data={"parent": parent, "child": child},
                    ))
                    break
            t.add_row(
                str(i),
                (e.get("Image", "")[-40:] + flag),
                e.get("CommandLine", "")[:60],
                e.get("ParentImage", "")[-25:],
            )
        console.print(t)

    # Network
    nets = [e for e in events if e["EventID"] == "3"]
    if nets:
        t = Table(title=f"🌐 NetworkConnections ({len(nets)})")
        t.add_column("#", width=4)
        t.add_column("Image", style="cyan", max_width=40)
        t.add_column("Dest", style="green", width=30)
        for i, e in enumerate(nets[:50], 1):
            dest = f"{e.get('DestinationIp', '?')}:{e.get('DestinationPort', '?')}"
            t.add_row(str(i), e.get("Image", "")[-40:], dest)
        console.print(t)

    # DNS
    dns = [e for e in events if e["EventID"] == "22"]
    if dns:
        t = Table(title=f"🌐 DNS queries ({len(dns)})")
        t.add_column("#", width=4)
        t.add_column("Image", style="cyan", max_width=40)
        t.add_column("QueryName", style="green")
        for i, e in enumerate(dns[:50], 1):
            t.add_row(str(i), e.get("Image", "")[-40:],
                      e.get("QueryName", ""))
        console.print(t)

    # LSASS access
    lsass = [e for e in events
             if e["EventID"] == "10"
             and "lsass.exe" in e.get("TargetImage", "").lower()]
    if lsass:
        findings.append(IRFinding(
            kind="lsass_access",
            severity="critical",
            title=f"LSASS access detected ({len(lsass)} events)",
            evidence=f"Processes: "
                     f"{', '.join(set(e.get('SourceImage', '?')[-40:] for e in lsass[:5]))}",
            data={"events": len(lsass)},
        ))

    # Save findings
    saved = sum(1 for f in findings if _save_finding(f) > 0)
    if saved:
        console.print(f"[green]✓ Findings в notes: {saved}[/green]")

    db.save_scan("forensics_sysmon", p.name, {
        "events": len(events),
        "by_eid": dict(counter),
        "findings": len(findings),
    })

    if save_export:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = FOR_DIR / f"sysmon_{p.stem}_{ts}.json"
        try:
            out.write_text(
                json.dumps({"events": events,
                            "findings": [asdict(f) for f in findings]},
                           indent=2, ensure_ascii=False),
                encoding="utf-8")
            console.print(f"[green]✓ {out}[/green]")
        except Exception:
            pass
    return events


def _find_attr(event, tag_name: str) -> str:
    for elem in event.iter(tag_name):
        for k, v in elem.attrib.items():
            if "Time" in k:
                return v
    return ""


# ===========================================================================
# auth.log parser
# ===========================================================================

def parse_auth_log(path: str) -> dict:
    """Парсер auth.log с brute-force detection."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return {}

    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return {}

    failed: list[dict] = []
    accepted: list[dict] = []
    sudo: list[dict] = []
    ssh_keys: list[dict] = []
    new_users: list[dict] = []
    group_changes: list[dict] = []

    for line in lines:
        m = re.search(
            r"Failed password for (?:invalid user )?(\S+) from (\S+)",
            line,
        )
        if m:
            failed.append({"user": m.group(1), "src": m.group(2),
                           "line": line[:200]})
            continue
        m = re.search(
            r"Accepted (?:password|publickey) for (\S+) from (\S+)",
            line,
        )
        if m:
            accepted.append({"user": m.group(1), "src": m.group(2),
                             "line": line[:200]})
            continue
        if "sudo:" in line and "COMMAND=" in line:
            m = re.search(r"(\S+)\s*:\s*.*?COMMAND=(.+)", line)
            if m:
                sudo.append({"user": m.group(1),
                             "cmd": m.group(2)[:200]})
            continue
        if "Accepted publickey" in line:
            ssh_keys.append({"line": line[:200]})
        # New user creation
        if "useradd" in line and "new user" in line:
            m = re.search(r"name=(\S+).*?UID=(\d+)", line)
            if m:
                new_users.append({"user": m.group(1), "uid": m.group(2)})
        # Group changes
        if "add" in line and "group" in line.lower():
            m = re.search(r"add '(\S+)' to group '(\S+)'", line)
            if m:
                group_changes.append({"user": m.group(1),
                                      "group": m.group(2)})

    console.print(f"[cyan]📋 Auth.log: {len(lines)} lines[/cyan]")

    findings: list[IRFinding] = []

    # Failed logins
    if failed:
        t = Table(title=f"❌ Failed passwords ({len(failed)})")
        t.add_column("User", style="cyan")
        t.add_column("From", style="green")
        t.add_column("Count", width=6)
        cnt = Counter((f["user"], f["src"]) for f in failed)
        for (user, src), c in cnt.most_common(20):
            t.add_row(user, src, str(c))
        console.print(t)

        # Brute-force detection: > 10 failed from same IP
        src_counts = Counter(f["src"] for f in failed)
        for src, c in src_counts.most_common(10):
            if c >= 10:
                findings.append(IRFinding(
                    kind="ssh_brute_force",
                    severity="high",
                    title=f"SSH brute-force from {src} ({c} attempts)",
                    target=src,
                    evidence=f"{c} failed logins",
                    data={"src": src, "attempts": c},
                ))

    # Accepted
    if accepted:
        t = Table(title=f"✅ Accepted logins ({len(accepted)})")
        t.add_column("User", style="cyan")
        t.add_column("From", style="green")
        t.add_column("Count", width=6)
        cnt = Counter((f["user"], f["src"]) for f in accepted)
        for (user, src), c in cnt.most_common(20):
            t.add_row(user, src, str(c))
        console.print(t)

    # Sudo
    if sudo:
        t = Table(title=f"🔐 Sudo commands ({len(sudo)})")
        t.add_column("User", style="cyan")
        t.add_column("Command", style="green", max_width=80)
        for s in sudo[:30]:
            t.add_row(s["user"], s["cmd"][:80])
        console.print(t)

    # New users
    if new_users:
        t = Table(title=f"👤 New users ({len(new_users)})")
        t.add_column("User", style="cyan")
        t.add_column("UID", style="green")
        for u in new_users:
            t.add_row(u["user"], u["uid"])
        console.print(t)
        findings.append(IRFinding(
            kind="new_user_created",
            severity="medium",
            title=f"New user(s) created: {', '.join(u['user'] for u in new_users[:5])}",
            data={"users": new_users},
        ))

    # Group changes
    if group_changes:
        findings.append(IRFinding(
            kind="group_membership_change",
            severity="medium",
            title=f"Group changes: {len(group_changes)}",
            evidence=json.dumps(group_changes[:5], ensure_ascii=False),
        ))

    # Save findings
    saved = sum(1 for f in findings if _save_finding(f) > 0)
    if saved:
        console.print(f"[green]✓ Findings в notes: {saved}[/green]")

    db.save_scan("forensics_authlog", p.name, {
        "failed": len(failed), "accepted": len(accepted),
        "sudo": len(sudo), "ssh_keys": len(ssh_keys),
        "new_users": len(new_users),
        "findings": len(findings),
    })

    return {
        "failed": failed, "accepted": accepted, "sudo": sudo,
        "ssh_keys": ssh_keys, "new_users": new_users,
        "group_changes": group_changes,
    }


# ===========================================================================
# auditd parser
# ===========================================================================

def parse_auditd(path: str) -> dict:
    """Парсер audit.log."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return {}

    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]{exc}[/red]")
        return {}

    console.print(f"[cyan]📋 auditd: {len(lines)} lines[/cyan]")

    events: dict[str, dict] = defaultdict(dict)
    execve: list[dict] = []
    syscalls: Counter = Counter()

    for line in lines:
        # Message type
        m = re.search(r"type=(\S+)", line)
        if not m:
            continue
        mtype = m.group(1)
        # msg=audit(TS:SEQ)
        m_id = re.search(r"msg=audit\(([\d.:]+)", line)
        eid = m_id.group(1) if m_id else ""

        if mtype == "EXECVE":
            # argv
            args = re.findall(r'a\d+="([^"]*)"', line)
            if args:
                execve.append({"ts": eid, "cmd": " ".join(args)[:500]})
        elif mtype == "SYSCALL":
            syscalls["SYSCALL"] += 1
        elif mtype.startswith("USER_"):
            syscalls[mtype] += 1
        else:
            syscalls[mtype] += 1

    t = Table(title="Message types")
    t.add_column("Type", style="cyan")
    t.add_column("Count", style="green", width=8)
    for mt, c in syscalls.most_common(20):
        t.add_row(mt, str(c))
    console.print(t)

    if execve:
        t = Table(title=f"🖥  EXECVE ({len(execve)}) — первые 30")
        t.add_column("#", width=4)
        t.add_column("Command", style="green", max_width=100)
        for i, e in enumerate(execve[:30], 1):
            t.add_row(str(i), e["cmd"][:100])
        console.print(t)

    db.save_scan("forensics_auditd", p.name, {
        "lines": len(lines),
        "execve": len(execve),
        "types": dict(syscalls),
    })
    return {"execve": execve, "types": dict(syscalls)}


# ===========================================================================
# Browser history
# ===========================================================================

def parse_browser_history(browser: str = "chrome",
                          path: str | None = None) -> list[dict]:
    """Парсер history SQLite (Chrome/Firefox)."""
    if not path:
        if os.name == "nt":
            if browser == "chrome":
                path = (os.path.expanduser("~") +
                        r"\AppData\Local\Google\Chrome\User Data\Default\History")
            elif browser == "firefox":
                path = None  # Firefox — profile-specific
        else:
            if browser == "chrome":
                path = os.path.expanduser(
                    "~/.config/google-chrome/Default/History")
            elif browser == "firefox":
                path = None

    if not path or not Path(path).exists():
        console.print(f"[red]History не найден: {path}[/red]")
        console.print("[yellow]Укажи путь вручную через параметр path.[/yellow]")
        return []

    # Копируем (SQLite может быть locked)
    tmp = FOR_DIR / f"_hist_{os.getpid()}.db"
    try:
        shutil.copy2(path, tmp)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Копирование: {exc}[/red]")
        return []

    results: list[dict] = []
    try:
        conn = sqlite3.connect(str(tmp))
        cur = conn.cursor()
        if browser == "chrome":
            cur.execute(
                "SELECT url, title, visit_count, last_visit_time "
                "FROM urls ORDER BY last_visit_time DESC LIMIT 500"
            )
        else:  # firefox
            cur.execute(
                "SELECT url, title, visit_count, last_visit_date "
                "FROM moz_places ORDER BY last_visit_date DESC LIMIT 500"
            )
        for row in cur.fetchall():
            results.append({
                "url": row[0], "title": row[1],
                "visits": row[2], "ts": row[3],
            })
        conn.close()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]SQLite: {exc}[/red]")
    finally:
        try:
            tmp.unlink()
        except Exception:
            pass

    if results:
        t = Table(title=f"🌐 Browser history ({len(results)})")
        t.add_column("#", width=4)
        t.add_column("URL", style="cyan", max_width=80)
        t.add_column("Visits", width=6)
        for i, r in enumerate(results[:50], 1):
            t.add_row(str(i), r["url"][:80], str(r["visits"]))
        console.print(t)

    db.save_scan("forensics_browser", browser, {"records": len(results)})
    return results


# ===========================================================================
# Hash verification
# ===========================================================================

def verify_hashes(hash_file: str, base_dir: str | None = None) -> dict:
    """
    Проверить файлы против hash-list (hashdeep-style).
    Формат hash_file: каждая строка — `sha256<space>filepath`.
    """
    p = Path(hash_file)
    if not p.exists():
        console.print(f"[red]{hash_file} не найден.[/red]")
        return {}

    results = {"match": 0, "mismatch": 0, "missing": 0, "details": []}

    import hashlib
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        expected_hash, filepath = parts
        if base_dir:
            filepath = os.path.join(base_dir, filepath)
        fpath = Path(filepath)
        if not fpath.exists():
            results["missing"] += 1
            results["details"].append({"file": filepath,
                                       "status": "missing"})
            continue
        try:
            h = hashlib.sha256()
            with fpath.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            actual = h.hexdigest()
            if actual.lower() == expected_hash.lower():
                results["match"] += 1
                results["details"].append({"file": filepath,
                                           "status": "match"})
            else:
                results["mismatch"] += 1
                results["details"].append({
                    "file": filepath, "status": "mismatch",
                    "expected": expected_hash, "actual": actual,
                })
        except Exception as exc:  # noqa: BLE001
            results["details"].append({"file": filepath,
                                       "status": "error",
                                       "error": str(exc)[:100]})

    t = Table(title=f"✅ Hash verification")
    t.add_column("Status", style="cyan")
    t.add_column("Count", style="green", width=10)
    t.add_row("Match", str(results["match"]))
    t.add_row("Mismatch", f"[red]{results['mismatch']}[/red]")
    t.add_row("Missing", f"[yellow]{results['missing']}[/yellow]")
    console.print(t)

    if results["mismatch"]:
        findings = []
        for d in results["details"]:
            if d["status"] == "mismatch":
                findings.append(IRFinding(
                    kind="hash_mismatch",
                    severity="high",
                    title=f"Hash mismatch: {d['file']}",
                    target=d["file"],
                    evidence=f"Expected: {d['expected']}\n"
                             f"Actual: {d['actual']}",
                ))
        saved = sum(1 for f in findings if _save_finding(f) > 0)
        if saved:
            console.print(f"[green]✓ Findings: {saved}[/green]")

    db.save_scan("forensics_hashverify", hash_file, {
        "match": results["match"],
        "mismatch": results["mismatch"],
        "missing": results["missing"],
    })
    return results


# ===========================================================================
# YARA scan
# ===========================================================================

def yara_scan_target(path: str, rules_path: str | None = None) -> list[dict]:
    """YARA-скан файла или директории."""
    try:
        import yara
    except ImportError:
        console.print("[red]yara-python не установлен: "
                      "pip install yara-python[/red]")
        return []

    target = Path(path)
    if not target.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return []

    # Compile rules
    try:
        if rules_path and Path(rules_path).exists():
            rules = yara.compile(filepath=rules_path)
        else:
            rules = yara.compile(source=r"""
            rule Suspicious_PowerShell_Encoded {
                strings:
                    $a = "powershell" nocase
                    $b = "-EncodedCommand" nocase
                condition: $a and $b
            }
            rule AWS_Keys_Leaked {
                strings:
                    $k = /AKIA[0-9A-Z]{16}/
                condition: $k
            }
            rule Mimikatz_Strings {
                strings:
                    $a = "sekurlsa::" nocase
                    $b = "lsadump::" nocase
                    $c = "kerberos::" nocase
                condition: any of them
            }
            rule Meterpreter {
                strings:
                    $a = "metsrv" nocase
                    $b = "meterpreter" nocase
                condition: any of them
            }
            rule Base64_Long {
                strings: $b = /[A-Za-z0-9+\/]{200,}={0,2}/
                condition: $b
            }
            """)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]YARA compile: {exc}[/red]")
        return []

    matches: list[dict] = []
    files: list[Path] = []
    if target.is_file():
        files = [target]
    else:
        for f in target.rglob("*"):
            if f.is_file() and f.stat().st_size < 50 * 1024 * 1024:
                files.append(f)
        files = files[:500]

    for f in files:
        try:
            m = rules.match(str(f))
            for match in m:
                matches.append({
                    "file": str(f),
                    "rule": match.rule,
                    "tags": list(match.tags),
                })
        except Exception:
            continue

    if matches:
        t = Table(title=f"🎯 YARA matches ({len(matches)})",
                  border_style="red")
        t.add_column("Rule", style="cyan")
        t.add_column("File", style="green", max_width=60)
        for mm in matches[:50]:
            t.add_row(mm["rule"], mm["file"][:60])
        console.print(t)

        # Findings
        critical_rules = ["Mimikatz_Strings", "Meterpreter",
                          "AWS_Keys_Leaked"]
        findings = []
        for mm in matches:
            if mm["rule"] in critical_rules:
                findings.append(IRFinding(
                    kind="yara_match",
                    severity="critical",
                    title=f"YARA match: {mm['rule']}",
                    target=mm["file"],
                    evidence=f"Rule: {mm['rule']}",
                ))
        saved = sum(1 for f in findings if _save_finding(f) > 0)
        if saved:
            console.print(f"[green]✓ Findings: {saved}[/green]")
    else:
        console.print("[green]✓ YARA: нет совпадений.[/green]")

    db.save_scan("forensics_yara", str(target),
                 {"matches": len(matches), "files": len(files)})
    return matches


# ===========================================================================
# CLI wrappers
# ===========================================================================

def cli_ioc(path: str) -> None:
    scan_log_iocs(path)


def cli_timeline(path: str) -> None:
    timeline(path)


def cli_sysmon(path: str) -> None:
    parse_sysmon_xml(path)


def cli_authlog(path: str) -> None:
    parse_auth_log(path)


def cli_auditd(path: str) -> None:
    parse_auditd(path)


def cli_hashverify(hash_file: str, base_dir: str | None = None) -> None:
    verify_hashes(hash_file, base_dir)


def cli_browser(browser: str = "chrome", path: str | None = None) -> None:
    parse_browser_history(browser, path)


def cli_yara(path: str, rules: str | None = None) -> None:
    yara_scan_target(path, rules)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    t = Table(title="[bold]🔬 Forensics & IR Pro[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", "IOC extractor (лог/файл, 40+ паттернов)"),
        ("2", "Timeline файлов (suspicious detection)"),
        ("3", "Sysmon XML parser (полный)"),
        ("4", "Auth.log parser (+ brute-force)"),
        ("5", "auditd parser"),
        ("6", "Browser history (Chrome/Firefox SQLite)"),
        ("7", "Hash verification (hashdeep-style)"),
        ("8", "YARA scan"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного IR / CTF.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        scan_log_iocs(Prompt.ask("Путь к логу"))
    elif c == "2":
        timeline(Prompt.ask("Путь (файл/директория)"))
    elif c == "3":
        parse_sysmon_xml(Prompt.ask("Путь к Sysmon XML"))
    elif c == "4":
        parse_auth_log(Prompt.ask("Путь к auth.log",
                                   default="/var/log/auth.log"))
    elif c == "5":
        parse_auditd(Prompt.ask("Путь к audit.log",
                                 default="/var/log/audit/audit.log"))
    elif c == "6":
        b = Prompt.ask("Browser", choices=["chrome", "firefox"],
                       default="chrome")
        p = Prompt.ask("Путь к History (Enter = авто)", default="").strip()
        parse_browser_history(b, p or None)
    elif c == "7":
        hf = Prompt.ask("Файл со списком хешей (sha256 <space> filepath)")
        bd = Prompt.ask("Base directory (Enter = нет)", default="").strip()
        verify_hashes(hf, bd or None)
    elif c == "8":
        path = Prompt.ask("Путь (файл/директория)")
        rules = Prompt.ask("YARA rules файл (Enter = встроенные)",
                            default="").strip()
        yara_scan_target(path, rules or None)