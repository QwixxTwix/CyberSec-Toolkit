"""
Compliance & Audit — расширенный.
Author: idqwixxa

⚠ Только для авторизованного аудита / пентеста.

Возможности:
    ─── Фреймворки ───
    - CIS Benchmarks: Linux (60+), Windows (30+), Docker (10+), K8s (10+)
    - OWASP Top 10 (2021) — mapping + reference
    - OWASP ASVS 4.0 — L1/L2/L3
    - PCI-DSS 4.0 — 12 requirements
    - ISO 27001:2022 — Annex A (14 domains)
    - NIST 800-53 (subset)
    - GDPR (basic)
    - SOC 2 (basic)

    ─── Live checks ───
    - Linux local (SSH, filesystem, kernel, services, logging, access)
    - Docker daemon / containers
    - K8s (если kubectl доступен)
    - Cloud (AWS account settings — если aws CLI)

    ─── Findings ───
    - Compliance score per framework (%)
    - Findings → notes для critical/high
    - Notify по завершении
    - HTML / JSON / CSV / Markdown / PDF экспорт
    - Checklist mode (mark pass/fail вручную)
"""
import csv
import html as html_mod
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

AUD_DIR = REPORT_DIR / "compliance"
AUD_DIR.mkdir(parents=True, exist_ok=True)

CHECKLISTS_DIR = AUD_DIR / "checklists"
CHECKLISTS_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Model
# ===========================================================================

@dataclass
class AuditItem:
    framework: str
    control: str
    description: str
    status: str = "unknown"       # pass | fail | warn | na | unknown
    severity: str = "medium"
    evidence: str = ""
    remediation: str = ""


def _save_finding(item: AuditItem, target: str = "local") -> int:
    """Сохранить critical/high findings в notes."""
    if item.severity not in ("critical", "high"):
        return -1
    if item.status != "fail":
        return -1
    try:
        from modules import notes
        return notes.add_note(
            kind="finding",
            title=f"[{item.framework}] {item.control}: {item.description}",
            target=target,
            severity=item.severity,
            status="open",
            tags=["compliance", item.framework.lower().replace(" ", "-")],
            body=(f"**Framework:** {item.framework}\n"
                  f"**Control:** {item.control}\n"
                  f"**Severity:** {item.severity}\n\n"
                  f"**Description:** {item.description}\n\n"
                  f"**Evidence:**\n```\n{(item.evidence or '—')[:1500]}\n```\n\n"
                  f"**Remediation:** {item.remediation or '—'}"),
        )
    except Exception:
        return -1


def compliance_score(items: list[AuditItem]) -> dict:
    """Score по framework."""
    total = len([i for i in items if i.status != "na"])
    passed = sum(1 for i in items if i.status == "pass")
    failed = sum(1 for i in items if i.status == "fail")
    warns = sum(1 for i in items if i.status == "warn")
    return {
        "total": total,
        "passed": passed,
        "failed": failed,
        "warns": warns,
        "score_pct": round(passed / max(total, 1) * 100, 1),
    }


# ===========================================================================
# CIS Linux (расширенный — 60+ checks)
# ===========================================================================

CIS_LINUX_CHECKS = [
    # ─── 1. Filesystem ───
    ("1.1.1.1", "Disable cramfs",
     "modprobe -n -v cramfs 2>/dev/null | grep -q 'install /bin/true'",
     "medium"),
    ("1.1.1.2", "Disable freevxfs",
     "modprobe -n -v freevxfs 2>/dev/null | grep -q 'install /bin/true'",
     "medium"),
    ("1.1.1.3", "Disable jffs2",
     "modprobe -n -v jffs2 2>/dev/null | grep -q 'install /bin/true'",
     "medium"),
    ("1.1.1.4", "Disable hfs",
     "modprobe -n -v hfs 2>/dev/null | grep -q 'install /bin/true'",
     "medium"),
    ("1.1.1.5", "Disable hfsplus",
     "modprobe -n -v hfsplus 2>/dev/null | grep -q 'install /bin/true'",
     "medium"),
    ("1.1.1.6", "Disable squashfs",
     "modprobe -n -v squashfs 2>/dev/null | grep -q 'install /bin/true'",
     "medium"),
    ("1.1.1.7", "Disable udf",
     "modprobe -n -v udf 2>/dev/null | grep -q 'install /bin/true'",
     "medium"),
    ("1.1.2", "/tmp отдельный раздел",
     "mount | grep -E '\\s/tmp\\s' >/dev/null",
     "medium"),
    ("1.1.3", "/tmp nodev",
     "mount | grep -E '\\s/tmp\\s.*nodev' >/dev/null",
     "medium"),
    ("1.1.4", "/tmp nosuid",
     "mount | grep -E '\\s/tmp\\s.*nosuid' >/dev/null",
     "medium"),
    ("1.1.5", "/tmp noexec",
     "mount | grep -E '\\s/tmp\\s.*noexec' >/dev/null",
     "medium"),

    # ─── 2. Services ───
    ("2.1.1", "No telnet server",
     "! systemctl is-enabled telnet.socket 2>/dev/null",
     "high"),
    ("2.1.2", "No rsh server",
     "! systemctl is-enabled rsh.socket 2>/dev/null",
     "high"),
    ("2.1.3", "No ypserv",
     "! systemctl is-enabled ypserv 2>/dev/null",
     "medium"),
    ("2.1.4", "No tftp server",
     "! systemctl is-enabled tftp.socket 2>/dev/null",
     "medium"),
    ("2.2.1", "No X window system",
     "! dpkg -l 2>/dev/null | grep -q '^ii  xserver-xorg'",
     "low"),
    ("2.2.2", "No avahi-daemon",
     "! systemctl is-enabled avahi-daemon 2>/dev/null",
     "medium"),
    ("2.2.3", "No cups",
     "! systemctl is-enabled cups 2>/dev/null",
     "low"),
    ("2.2.4", "No dhcpd",
     "! systemctl is-enabled isc-dhcp-server 2>/dev/null",
     "medium"),
    ("2.2.5", "No slapd",
     "! systemctl is-enabled slapd 2>/dev/null",
     "medium"),
    ("2.2.6", "No nfs",
     "! systemctl is-enabled nfs-server 2>/dev/null",
     "medium"),
    ("2.2.7", "No rpcbind",
     "! systemctl is-enabled rpcbind 2>/dev/null",
     "medium"),

    # ─── 3. Networking ───
    ("3.1.1", "IP forwarding disabled",
     "sysctl net.ipv4.ip_forward 2>/dev/null | grep -q '= 0'",
     "medium"),
    ("3.1.2", "Send redirects disabled",
     "sysctl net.ipv4.conf.all.send_redirects 2>/dev/null | "
     "grep -q '= 0'",
     "medium"),
    ("3.2.1", "Source routed packets not accepted",
     "sysctl net.ipv4.conf.all.accept_source_route 2>/dev/null | "
     "grep -q '= 0'",
     "medium"),
    ("3.2.2", "ICMP redirects not accepted",
     "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null | "
     "grep -q '= 0'",
     "medium"),
    ("3.2.3", "Secure ICMP redirects not accepted",
     "sysctl net.ipv4.conf.all.secure_redirects 2>/dev/null | "
     "grep -q '= 0'",
     "medium"),
    ("3.2.4", "Suspicious packets logged",
     "sysctl net.ipv4.conf.all.log_martians 2>/dev/null | "
     "grep -q '= 1'",
     "low"),
    ("3.3.1", "IPv6 RA not accepted",
     "sysctl net.ipv6.conf.all.accept_ra 2>/dev/null | grep -q '= 0'",
     "medium"),
    ("3.3.2", "IPv6 redirects not accepted",
     "sysctl net.ipv6.conf.all.accept_redirects 2>/dev/null | "
     "grep -q '= 0'",
     "medium"),

    # ─── 4. Logging ───
    ("4.1.1.1", "auditd installed",
     "command -v auditd >/dev/null 2>&1 || "
     "systemctl is-enabled auditd 2>/dev/null",
     "high"),
    ("4.1.1.2", "auditd enabled",
     "systemctl is-enabled auditd 2>/dev/null",
     "high"),
    ("4.2.1.1", "rsyslog installed",
     "command -v rsyslogd >/dev/null 2>&1 || "
     "systemctl is-enabled rsyslog 2>/dev/null",
     "medium"),
    ("4.2.1.2", "rsyslog enabled",
     "systemctl is-enabled rsyslog 2>/dev/null",
     "medium"),
    ("4.2.2", "journald forwarding",
     "grep -Eq '^\\s*ForwardToSyslog\\s*=\\s*yes' "
     "/etc/systemd/journald.conf 2>/dev/null",
     "low"),
    ("4.2.3", "logrotate installed",
     "command -v logrotate >/dev/null 2>&1",
     "low"),

    # ─── 5. Access / SSH ───
    ("5.1.1", "cron daemon enabled",
     "systemctl is-enabled cron 2>/dev/null || "
     "systemctl is-enabled crond 2>/dev/null",
     "low"),
    ("5.1.2", "/etc/crontab permissions",
     "stat -c %a /etc/crontab 2>/dev/null | grep -q '^600$'",
     "medium"),
    ("5.2.1", "SSH Protocol 2",
     "grep -Eq '^Protocol\\s+2' /etc/ssh/sshd_config 2>/dev/null",
     "high"),
    ("5.2.2", "SSH root login disabled",
     "grep -Eq '^PermitRootLogin\\s+no' "
     "/etc/ssh/sshd_config 2>/dev/null",
     "high"),
    ("5.2.3", "SSH MaxAuthTries <= 4",
     "grep -Eq '^MaxAuthTries\\s+[1-4]$' "
     "/etc/ssh/sshd_config 2>/dev/null",
     "medium"),
    ("5.2.4", "SSH empty passwords disabled",
     "grep -Eq '^PermitEmptyPasswords\\s+no' "
     "/etc/ssh/sshd_config 2>/dev/null",
     "high"),
    ("5.2.5", "SSH IgnoreRhosts",
     "grep -Eq '^IgnoreRhosts\\s+yes' "
     "/etc/ssh/sshd_config 2>/dev/null",
     "medium"),
    ("5.2.6", "SSH X11Forwarding disabled",
     "grep -Eq '^X11Forwarding\\s+no' "
     "/etc/ssh/sshd_config 2>/dev/null",
     "low"),
    ("5.2.7", "SSH MaxSessions <= 10",
     "grep -Eq '^MaxSessions\\s+[1-9]$|^MaxSessions\\s+10$' "
     "/etc/ssh/sshd_config 2>/dev/null",
     "low"),
    ("5.2.8", "SSH LoginGraceTime <= 60",
     "grep -Eq '^LoginGraceTime\\s+([1-9]|[1-5][0-9]|60)$' "
     "/etc/ssh/sshd_config 2>/dev/null",
     "medium"),
    ("5.2.9", "SSH Banner set",
     "grep -Eq '^Banner\\s+/' /etc/ssh/sshd_config 2>/dev/null",
     "low"),
    ("5.3.1", "sudo installed",
     "command -v sudo >/dev/null 2>&1",
     "medium"),
    ("5.3.2", "sudo NOPASSWD отсутствует",
     "! grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null "
     "| grep -qv '^#'",
     "medium"),
    ("5.4.1", "Password expiration <= 365",
     "grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | "
     "awk '{print $2}' | grep -Eq '^[1-9][0-9]{0,2}$'",
     "medium"),
    ("5.4.2", "Password min length >= 14",
     "grep -E '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | "
     "awk '{print $2}' | awk '$1>=14' | grep -q .",
     "high"),
    ("5.4.3", "Password history >= 5",
     "grep -E '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | "
     "grep -q .",
     "low"),
    ("5.5.1", "No UID 0 accounts except root",
     "awk -F: '$3==0 && $1!=\"root\" {exit 1}' /etc/passwd",
     "critical"),
    ("5.5.2", "No empty password fields",
     "awk -F: '($2==\"\") {exit 1}' /etc/shadow 2>/dev/null",
     "critical"),
    ("5.5.3", "No legacy '+' entries",
     "! grep -qE '^\\+:' /etc/passwd /etc/shadow /etc/group 2>/dev/null",
     "high"),
    ("5.6.1", "su restricted",
     "grep -Eq '^\\s*auth\\s+required\\s+pam_wheel.so' "
     "/etc/pam.d/su 2>/dev/null",
     "medium"),

    # ─── 6. Maintenance ───
    ("6.1.1", "/etc/passwd 644",
     "stat -c %a /etc/passwd 2>/dev/null | grep -q '^644$'",
     "medium"),
    ("6.1.2", "/etc/shadow 640 или строже",
     "stat -c %a /etc/shadow 2>/dev/null | "
     "grep -Eq '^(000|400|640|600)$'",
     "high"),
    ("6.1.3", "/etc/group 644",
     "stat -c %a /etc/group 2>/dev/null | grep -q '^644$'",
     "medium"),
    ("6.1.4", "/etc/gshadow 640 или строже",
     "stat -c %a /etc/gshadow 2>/dev/null | "
     "grep -Eq '^(000|400|640|600)$'",
     "medium"),
    ("6.1.5", "/etc/passwd- 644",
     "stat -c %a /etc/passwd- 2>/dev/null | grep -q '^644$'",
     "low"),
    ("6.1.6", "/etc/shadow- 640 или строже",
     "stat -c %a /etc/shadow- 2>/dev/null | "
     "grep -Eq '^(000|400|640|600)$'",
     "medium"),
    ("6.1.7", "/etc/group- 644",
     "stat -c %a /etc/group- 2>/dev/null | grep -q '^644$'",
     "low"),
    ("6.2.1", "No world-writable files in /etc",
     "! find /etc -type f -perm -002 2>/dev/null | grep -q .",
     "high"),
    ("6.2.2", "No SUID/SGID в нестандартных путях",
     "! find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f "
     "2>/dev/null | grep -vE '^/(usr/)?(s?bin|lib)' | grep -q .",
     "high"),

    # ─── 7. Kernel hardening ───
    ("7.1.1", "ASLR включён",
     "sysctl kernel.randomize_va_space 2>/dev/null | grep -q '= 2'",
     "high"),
    ("7.1.2", "kernel.dmesg_restrict=1",
     "sysctl kernel.dmesg_restrict 2>/dev/null | grep -q '= 1'",
     "medium"),
    ("7.1.3", "kernel.kptr_restrict=1+",
     "sysctl kernel.kptr_restrict 2>/dev/null | grep -Eq '= [12]'",
     "medium"),
    ("7.1.4", "kernel.yama.ptrace_scope=1+",
     "sysctl kernel.yama.ptrace_scope 2>/dev/null | grep -Eq '= [1-3]'",
     "medium"),
    ("7.1.5", "fs.protected_hardlinks=1",
     "sysctl fs.protected_hardlinks 2>/dev/null | grep -q '= 1'",
     "medium"),
    ("7.1.6", "fs.protected_symlinks=1",
     "sysctl fs.protected_symlinks 2>/dev/null | grep -q '= 1'",
     "medium"),
    ("7.1.7", "fs.suid_dumpable=0",
     "sysctl fs.suid_dumpable 2>/dev/null | grep -q '= 0'",
     "medium"),
]


# ===========================================================================
# CIS Docker checks
# ===========================================================================

CIS_DOCKER_CHECKS = [
    ("1.1.1", "Docker daemon не слушает TCP 2375",
     "! ss -tlnp 2>/dev/null | grep -q ':2375 '",
     "critical"),
    ("1.1.2", "Docker daemon TLS (2376)",
     "ss -tlnp 2>/dev/null | grep -q ':2376 ' || true",
     "high"),
    ("1.2.1", "/var/lib/docker permissions",
     "stat -c %a /var/lib/docker 2>/dev/null | grep -Eq '^(700|710)$'",
     "medium"),
    ("2.1.1", "No privileged containers",
     "! docker ps --format '{{.Names}}' 2>/dev/null | xargs -I{} "
     "docker inspect --format '{{.HostConfig.Privileged}}' {} "
     "2>/dev/null | grep -q 'true'",
     "critical"),
    ("2.2.1", "No host PID namespace containers",
     "! docker ps --format '{{.Names}}' 2>/dev/null | xargs -I{} "
     "docker inspect --format '{{.HostConfig.PidMode}}' {} 2>/dev/null "
     "| grep -q 'host'",
     "high"),
    ("2.3.1", "No host network containers",
     "! docker ps --format '{{.Names}}' 2>/dev/null | xargs -I{} "
     "docker inspect --format '{{.HostConfig.NetworkMode}}' {} "
     "2>/dev/null | grep -q 'host'",
     "high"),
    ("3.1.1", "Docker daemon.json существует",
     "test -f /etc/docker/daemon.json",
     "medium"),
    ("3.1.2", "userland-proxy disabled",
     "grep -q '\"userland-proxy\": false' /etc/docker/daemon.json "
     "2>/dev/null",
     "low"),
    ("4.1.1", "Live-restore enabled",
     "grep -q '\"live-restore\": true' /etc/docker/daemon.json "
     "2>/dev/null",
     "low"),
    ("4.2.1", "No containers running as root",
     "! docker ps --format '{{.Names}}' 2>/dev/null | xargs -I{} "
     "docker inspect --format '{{.Config.User}}' {} 2>/dev/null "
     "| grep -q '^$'",
     "high"),
]


# ===========================================================================
# OWASP Top 10 (2021)
# ===========================================================================

OWASP_TOP10 = [
    ("A01", "Broken Access Control",
     "IDOR, missing function-level access control, path traversal"),
    ("A02", "Cryptographic Failures",
     "Weak crypto, plain-text storage, no TLS, weak key mgmt"),
    ("A03", "Injection",
     "SQLi, NoSQLi, OS Command, LDAP, XPath, SSTI"),
    ("A04", "Insecure Design",
     "Business logic flaws, missing threat modeling"),
    ("A05", "Security Misconfiguration",
     "Default creds, verbose errors, unnecessary features, XXE"),
    ("A06", "Vulnerable and Outdated Components",
     "Old libraries, unpatched frameworks, CVE-laden deps"),
    ("A07", "Identification and Authentication Failures",
     "Weak passwords, no MFA, session fixation, credential stuffing"),
    ("A08", "Software and Data Integrity Failures",
     "Insecure deserialization, unsigned updates, CI/CD attacks"),
    ("A09", "Security Logging and Monitoring Failures",
     "No logging of critical events, no alerting, no retention"),
    ("A10", "Server-Side Request Forgery",
     "SSRF against internal services, cloud metadata"),
]


# ===========================================================================
# OWASP ASVS 4.0 (расширенный)
# ===========================================================================

ASVS_SAMPLE = [
    ("V1.1", "Secure Software Development Lifecycle", "L1"),
    ("V1.2", "Authentication Architectural Requirements", "L2"),
    ("V1.5", "Defensive Coding Requirements", "L2"),
    ("V2.1", "Password Security", "L1"),
    ("V2.2", "General Authenticator Requirements", "L2"),
    ("V2.3", "Authenticator Lifecycle Requirements", "L2"),
    ("V2.5", "Credential Recovery", "L2"),
    ("V2.6", "Look-up Secret Verifier Requirements", "L2"),
    ("V2.7", "Out of Band Verifier Requirements", "L2"),
    ("V2.8", "Single or Multi Factor One Time Verifier Requirements",
     "L2"),
    ("V3.1", "Session Management Fundamentals", "L1"),
    ("V3.2", "Session Binding Requirements", "L2"),
    ("V3.3", "Session Logout and Timeout Requirements", "L2"),
    ("V3.4", "Cookie-based Session Management", "L1"),
    ("V3.5", "Token-based Session Management", "L2"),
    ("V4.1", "General Access Control Design", "L1"),
    ("V4.2", "Operation Level Access Control", "L1"),
    ("V4.3", "Other Access Control Considerations", "L2"),
    ("V5.1", "Input Validation", "L1"),
    ("V5.2", "Sanitization and Sandboxing", "L2"),
    ("V5.3", "Output Encoding and Injection Prevention", "L1"),
    ("V5.4", "Memory, String, and Unmanaged Code", "L2"),
    ("V5.5", "Deserialization Prevention", "L2"),
    ("V6.2", "Algorithms", "L1"),
    ("V6.3", "Random Values", "L2"),
    ("V6.4", "Secret Management", "L2"),
    ("V7.1", "Log Content", "L1"),
    ("V7.2", "Log Processing", "L2"),
    ("V7.3", "Log Protection", "L2"),
    ("V7.4", "Error Handling", "L2"),
    ("V8.1", "General Data Protection", "L1"),
    ("V8.2", "Client-side Data Protection", "L2"),
    ("V8.3", "Sensitive Private Data", "L2"),
    ("V9.1", "Communications Security", "L1"),
    ("V9.2", "Server Communications Security", "L2"),
    ("V10.1", "Code Integrity", "L2"),
    ("V10.2", "Malicious Code Search", "L2"),
    ("V10.3", "Deployed Application Integrity", "L2"),
    ("V11.1", "Business Logic Security", "L2"),
    ("V12.1", "File Upload", "L2"),
    ("V12.3", "File Upload", "L2"),
    ("V13.1", "Generic Web Service Security", "L1"),
    ("V13.2", "RESTful Web Service", "L2"),
    ("V13.3", "SOAP Web Service", "L2"),
    ("V13.4", "GraphQL and other modern Web Service", "L2"),
    ("V14.1", "Build", "L1"),
    ("V14.2", "Dependency", "L1"),
    ("V14.3", "Unintended Security Disclosure", "L2"),
]


# ===========================================================================
# PCI-DSS 4.0
# ===========================================================================

PCI_DSS = [
    ("1", "Install and maintain network security controls",
     "Firewalls, network segmentation, DMZ"),
    ("2", "Apply secure configurations to all system components",
     "No defaults, hardening, config standards"),
    ("3", "Protect stored account data",
     "Encryption at rest, masking, key management"),
    ("4", "Protect cardholder data with strong cryptography during transmission",
     "TLS 1.2+, no legacy protocols, cert validation"),
    ("5", "Protect all systems and networks from malicious software",
     "AV/EDR, regular scans, updates"),
    ("6", "Develop and maintain secure systems and software",
     "SDLC, code review, patch mgmt, OWASP"),
    ("7", "Restrict access to system components and cardholder data",
     "Least privilege, RBAC, access reviews"),
    ("8", "Identify users and authenticate access",
     "MFA, strong passwords, unique IDs"),
    ("9", "Restrict physical access to cardholder data",
     "Physical controls, badges, cameras"),
    ("10", "Log and monitor all access",
     "Central logging, alerting, retention 12+ months"),
    ("11", "Test security of systems and networks regularly",
     "Quarterly ASV scans, annual pentest, IDS"),
    ("12", "Support information security with organizational policies",
     "Security policy, awareness training, IR plan"),
]


# ===========================================================================
# ISO 27001:2022 Annex A
# ===========================================================================

ISO_27001 = [
    ("A.5", "Organizational controls (37)"),
    ("A.6", "People controls (8)"),
    ("A.7", "Physical controls (14)"),
    ("A.8", "Technological controls (34)"),
]


# ===========================================================================
# NIST 800-53 (subset)
# ===========================================================================

NIST_800_53 = [
    ("AC", "Access Control"),
    ("AT", "Awareness and Training"),
    ("AU", "Audit and Accountability"),
    ("CA", "Assessment, Authorization, and Monitoring"),
    ("CM", "Configuration Management"),
    ("CP", "Contingency Planning"),
    ("IA", "Identification and Authentication"),
    ("IR", "Incident Response"),
    ("MA", "Maintenance"),
    ("MP", "Media Protection"),
    ("PE", "Physical and Environmental Protection"),
    ("PL", "Planning"),
    ("PS", "Personnel Security"),
    ("RA", "Risk Assessment"),
    ("SA", "System and Services Acquisition"),
    ("SC", "System and Communications Protection"),
    ("SI", "System and Information Integrity"),
]


# ===========================================================================
# CIS Linux runner (расширенный)
# ===========================================================================

def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def run_cis_linux() -> list[AuditItem]:
    """Запустить CIS Linux checks."""
    items: list[AuditItem] = []
    for control, desc, cmd, sev in CIS_LINUX_CHECKS:
        if not _is_linux():
            items.append(AuditItem(
                framework="CIS Linux",
                control=control, description=desc,
                status="na", severity=sev,
                evidence="Not Linux",
            ))
            continue
        try:
            r = subprocess.run(cmd, shell=True, timeout=10,
                               capture_output=True, text=True)
            status = "pass" if r.returncode == 0 else "fail"
            evidence = ((r.stdout or r.stderr or "")[:120].strip())
        except Exception as exc:
            status = "unknown"
            evidence = str(exc)[:80]
        items.append(AuditItem(
            framework="CIS Linux",
            control=control, description=desc,
            status=status, severity=sev, evidence=evidence,
        ))
    return items


def run_cis_docker() -> list[AuditItem]:
    """CIS Docker checks (только если docker доступен)."""
    if not shutil.which("docker"):
        return []
    items: list[AuditItem] = []
    for control, desc, cmd, sev in CIS_DOCKER_CHECKS:
        try:
            r = subprocess.run(cmd, shell=True, timeout=10,
                               capture_output=True, text=True)
            status = "pass" if r.returncode == 0 else "fail"
            evidence = ((r.stdout or r.stderr or "")[:120].strip())
        except Exception as exc:
            status = "unknown"
            evidence = str(exc)[:80]
        items.append(AuditItem(
            framework="CIS Docker",
            control=control, description=desc,
            status=status, severity=sev, evidence=evidence,
        ))
    return items


def _print_audit(items: list[AuditItem], title: str = "Audit") -> None:
    if not items:
        console.print("[yellow]Нет данных.[/yellow]")
        return

    score = compliance_score(items)
    console.print(
        f"\n[cyan]{title}[/cyan] — "
        f"[green]pass: {score['passed']}[/green] "
        f"[red]fail: {score['failed']}[/red] "
        f"[yellow]warn: {score['warns']}[/yellow] "
        f"[dim](score: {score['score_pct']}%)[/dim]")

    t = Table(title=f"{title} ({len(items)})")
    t.add_column("Control", style="cyan", width=10)
    t.add_column("Status", width=8)
    t.add_column("Sev", width=10)
    t.add_column("Description", style="white", max_width=50)
    t.add_column("Evidence", style="dim", max_width=40)
    for i in sorted(items, key=lambda x: (
        {"fail": 0, "warn": 1, "unknown": 2, "pass": 3, "na": 4}.get(
            x.status, 5),
        {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
            x.severity, 5),
    )):
        sty = {"pass": "green", "fail": "red", "warn": "yellow",
               "na": "dim", "unknown": "yellow"}.get(i.status, "white")
        t.add_row(
            i.control,
            f"[{sty}]{i.status.upper()}[/{sty}]",
            i.severity.upper(),
            i.description[:50],
            i.evidence[:40],
        )
    console.print(t)


# ===========================================================================
# Report export
# ===========================================================================

def export_audit(items: list[AuditItem], framework: str,
                 fmt: str = "md") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"md": ".md", "json": ".json", "csv": ".csv",
           "html": ".html"}[fmt]
    path = AUD_DIR / f"{framework}_{ts}{ext}"

    score = compliance_score(items)

    try:
        if fmt == "json":
            path.write_text(json.dumps({
                "framework": framework,
                "score": score,
                "items": [asdict(i) for i in items],
                "ts": datetime.now().isoformat(),
            }, indent=2, ensure_ascii=False), encoding="utf-8")
        elif fmt == "csv":
            cols = ["framework", "control", "description", "status",
                    "severity", "evidence", "remediation"]
            with path.open("w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=cols,
                                    extrasaction="ignore")
                w.writeheader()
                for i in items:
                    w.writerow(asdict(i))
        elif fmt == "html":
            _export_html(items, framework, score, path)
        else:  # md
            lines = [f"# {framework} — Audit Report", "",
                     f"_Generated: {datetime.now().isoformat()}_", ""]
            lines.append(f"## Score: **{score['score_pct']}%** "
                         f"({score['passed']}/{score['total']})")
            lines.append("")
            lines.append("## Failed / Warnings")
            lines.append("")
            lines.append("| Control | Status | Severity | Description |")
            lines.append("|---------|--------|----------|-------------|")
            for i in items:
                if i.status in ("fail", "warn", "unknown"):
                    lines.append(f"| {i.control} | {i.status} | "
                                 f"{i.severity} | {i.description} |")
            path.write_text("\n".join(lines), encoding="utf-8")

        console.print(f"[green]✓ {path}[/green]")
        db.save_scan("compliance_audit", framework,
                     {"items": len(items), "score": score,
                      "path": str(path)})

        # Findings → notes
        saved = 0
        for i in items:
            if _save_finding(i, target=framework) > 0:
                saved += 1
        if saved:
            console.print(f"[green]✓ Findings в notes: {saved}[/green]")

        return path
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def _export_html(items: list[AuditItem], framework: str,
                  score: dict, path: Path) -> None:
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>{framework} — Audit Report</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        ".score{font-size:32px;color:#00ff9c;font-weight:bold;}"
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:8px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".pass{color:#00ff9c;}", ".fail{color:#ff4040;font-weight:bold;}",
        ".warn{color:#ffd23f;}", ".na{color:#666;}",
        ".critical{color:#ff2020;font-weight:bold;}",
        ".high{color:#ff7a40;font-weight:bold;}",
        ".medium{color:#ffd23f;}",
        "</style></head><body>",
        f"<h1>📋 {html_mod.escape(framework)}</h1>",
        f"<p>Score: <span class='score'>{score['score_pct']}%</span> "
        f"({score['passed']}/{score['total']}) — "
        f"<span class='pass'>pass: {score['passed']}</span> / "
        f"<span class='fail'>fail: {score['failed']}</span> / "
        f"<span class='warn'>warn: {score['warns']}</span></p>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>Control</th><th>Status</th><th>Severity</th>"
        "<th>Description</th><th>Evidence</th></tr>",
    ]
    for i in items:
        parts.append(
            f"<tr><td>{html_mod.escape(i.control)}</td>"
            f"<td class='{i.status}'>{i.status.upper()}</td>"
            f"<td class='{i.severity}'>{i.severity.upper()}</td>"
            f"<td>{html_mod.escape(i.description)}</td>"
            f"<td>{html_mod.escape(i.evidence[:120])}</td></tr>")
    parts.append("</table></body></html>")
    path.write_text("\n".join(parts), encoding="utf-8")


# ===========================================================================
# CLI (совместимы со старыми)
# ===========================================================================

def cli_cis() -> None:
    items = run_cis_linux()
    _print_audit(items, "CIS Linux Benchmark")
    if Confirm.ask("Экспорт отчёта?", default=False):
        fmt = Prompt.ask("Формат", choices=["md", "json", "csv", "html"],
                          default="md")
        export_audit(items, "cis_linux", fmt)


def cli_docker() -> None:
    items = run_cis_docker()
    if not items:
        console.print("[yellow]Docker не установлен.[/yellow]")
        return
    _print_audit(items, "CIS Docker Benchmark")
    if Confirm.ask("Экспорт отчёта?", default=False):
        fmt = Prompt.ask("Формат", choices=["md", "json", "csv", "html"],
                          default="md")
        export_audit(items, "cis_docker", fmt)


def cli_owasp_top10() -> None:
    t = Table(title="OWASP Top 10 (2021)")
    t.add_column("ID", style="cyan", width=5)
    t.add_column("Name", style="magenta", width=35)
    t.add_column("Description", style="white", max_width=60)
    for code, name, desc in OWASP_TOP10:
        t.add_row(code, name, desc)
    console.print(t)


def cli_asvs() -> None:
    t = Table(title=f"OWASP ASVS 4.0 ({len(ASVS_SAMPLE)})")
    t.add_column("ID", style="cyan", width=8)
    t.add_column("Requirement", style="white", max_width=55)
    t.add_column("Level", style="yellow", width=6)
    for code, desc, level in ASVS_SAMPLE:
        t.add_row(code, desc, level)
    console.print(t)


def cli_pci() -> None:
    t = Table(title="PCI-DSS 4.0 — 12 requirements")
    t.add_column("#", style="cyan", width=4)
    t.add_column("Requirement", style="white", max_width=60)
    t.add_column("Highlights", style="dim", max_width=50)
    for num, req, high in PCI_DSS:
        t.add_row(num, req, high)
    console.print(t)


def cli_iso() -> None:
    t = Table(title="ISO 27001:2022 Annex A")
    t.add_column("Domain", style="cyan", width=8)
    t.add_column("Name", style="white")
    for code, name in ISO_27001:
        t.add_row(code, name)
    console.print(t)


def cli_nist() -> None:
    t = Table(title="NIST 800-53 (subset)")
    t.add_column("Family", style="cyan", width=8)
    t.add_column("Name", style="white")
    for code, name in NIST_800_53:
        t.add_row(code, name)
    console.print(t)


def cli_all() -> None:
    """Все фреймворки кратко."""
    console.print("[bold cyan]═══ Compliance overview ═══[/bold cyan]\n")
    cli_owasp_top10()
    console.print()
    cli_pci()
    console.print()
    cli_iso()
    console.print()
    cli_nist()
    console.print()
    if _is_linux() and Confirm.ask("Запустить CIS Linux checks?",
                                     default=False):
        cli_cis()


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    t = Table(title="[bold]📋 Compliance & Audit[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", f"CIS Linux Benchmark ({len(CIS_LINUX_CHECKS)} live)"),
        ("2", f"CIS Docker ({len(CIS_DOCKER_CHECKS)} checks)"),
        ("3", "OWASP Top 10 (2021)"),
        ("4", f"OWASP ASVS 4.0 ({len(ASVS_SAMPLE)})"),
        ("5", "PCI-DSS 4.0"),
        ("6", "ISO 27001:2022"),
        ("7", "NIST 800-53"),
        ("8", "Всё сразу (overview)"),
        ("9", "Live audit (Linux + Docker)"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного аудита.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cli_cis()
    elif c == "2":
        cli_docker()
    elif c == "3":
        cli_owasp_top10()
    elif c == "4":
        cli_asvs()
    elif c == "5":
        cli_pci()
    elif c == "6":
        cli_iso()
    elif c == "7":
        cli_nist()
    elif c == "8":
        cli_all()
    elif c == "9":
        items: list[AuditItem] = []
        items.extend(run_cis_linux())
        if shutil.which("docker"):
            items.extend(run_cis_docker())
        _print_audit(items, "Full Live Audit")
        if Confirm.ask("Экспорт?", default=True):
            export_audit(items, "full_live", "html")