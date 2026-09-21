"""
Threat Hunting (extended).
Author: idqwixxa

⚠ Только для авторизованного IR / threat hunting / CTF.

Возможности:
    ─── Sigma rules (расширено до 20+) ───
    - Execution / Persistence / Privilege Escalation
    - Credential Access / Lateral Movement / Defense Evasion
    - Command & Control / Exfiltration / Impact

    ─── Hunt playbooks (расширено) ───
    - 12 тактик с KQL / PowerShell / Sysmon-запросами
    - Каждая тактика = 3-7 запросов

    ─── MITRE ATT&CK (30+ TTPs) ───
    - Tactic / Technique / Detection advice
    - Экспорт в MITRE Navigator layer (JSON)

    ─── Экспорт ───
    - Sigma rules → YAML-файлы (директория)
    - Playbooks → Markdown / HTML
    - MITRE → JSON (Navigator) / CSV
    - Full HTML dashboard (rules + playbooks + MITRE)

    ─── Интеграция ───
    - Findings → notes (при поиске по TTP)
    - Notify (при экспорте слоя / hunting session)
"""
import csv
import html as html_mod
import json
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

HUNT_DIR = REPORT_DIR / "hunting"
HUNT_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class THFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: THFinding) -> int:
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
            tags=["threat-hunting", f.kind],
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
# Sigma rules (расширено)
# ===========================================================================

SIGMA_RULES = {
    "suspicious_powershell": """
title: Suspicious PowerShell Encoded Command
id: 1a2b3c4d-1111-2222-3333-444455556666
status: experimental
description: Detects base64-encoded PowerShell execution
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: CyberSec Toolkit
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
            - ' -e '
            - ' -ec '
    condition: selection
falsepositives:
    - Admin scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
""",
    "suspicious_wmic": """
title: Suspicious WMIC execution
id: 2b3c4d5e-2222-3333-4444-555566667777
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains:
            - 'process call create'
            - 'shadowcopy delete'
            - 'computersystem'
            - 'product get name'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1047
""",
    "lsass_dump": """
title: LSASS Memory Dump
id: 3c4d5e6f-3333-4444-5555-666677778888
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1038'
            - '0x1fffff'
            - '0x1410'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
""",
    "mimikatz": """
title: Mimikatz CommandLine patterns
id: 4d5e6f7a-4444-5555-6666-777788889999
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa::'
            - 'lsadump::'
            - 'kerberos::'
            - 'mimikatz'
            - 'dpapi::'
    condition: selection
level: critical
tags:
    - attack.credential_access
""",
    "shadow_copy_deletion": """
title: Shadow Copy Deletion
id: 5e6f7a8b-5555-6666-7777-888899990000
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'vssadmin delete shadows'
            - 'wmic shadowcopy delete'
            - 'Get-WmiObject Win32_ShadowCopy'
            - 'wbadmin delete catalog'
        CommandLine|contains: 'delete'
    condition: selection
level: critical
tags:
    - attack.impact
    - attack.t1490
""",
    "certutil_decode": """
title: Certutil Download/Decode
id: 6f7a8b9c-6666-7777-8888-999900001111
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-decode'
            - '-decodehex'
            - '-verifyctl'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1140
""",
    "schtasks_persistence": """
title: Suspicious Scheduled Task Creation
id: 7a8b9c0d-7777-8888-9999-000011112222
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains:
            - '/create'
            - '/sc onlogon'
            - '/sc onstart'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1053.005
""",
    "dns_exfil": """
title: Potential DNS Exfiltration
id: 8b9c0d1e-8888-9999-0000-111122223333
logsource:
    category: dns_query
detection:
    selection:
        QueryName|re: '^[a-z0-9]{30,}\\.'
    condition: selection
level: medium
tags:
    - attack.exfiltration
    - attack.t1048.003
""",
    "suspicious_lnk": """
title: Suspicious LNK file creation (USB / phishing)
id: 9c0d1e2f-9999-0000-1111-222233334444
logsource:
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|endswith: '.lnk'
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
    condition: selection
level: high
tags:
    - attack.initial_access
    - attack.t1566.001
""",
    "run_key_persistence": """
title: Registry Run Key Modification
id: aabbccdd-1111-2222-3333-444455557777
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\\CurrentVersion\\Run\\'
            - '\\CurrentVersion\\RunOnce\\'
            - '\\CurrentVersion\\RunServices\\'
        Details|re: '.*\\.(exe|dll|ps1|vbs|bat|cmd|js|hta)$'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1547.001
""",
    "office_spawning_shell": """
title: Office Spawning Shell
id: bbaaccdd-2222-3333-4444-555566668888
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\\winword.exe'
            - '\\excel.exe'
            - '\\powerpnt.exe'
            - '\\outlook.exe'
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\mshta.exe'
            - '\\rundll32.exe'
    condition: selection
level: critical
tags:
    - attack.execution
    - attack.t1204.002
""",
    "kerberoasting": """
title: Kerberoasting (TGS-REQ for SPN)
id: ccaaddbb-3333-4444-5555-666677779999
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4769
        TicketEncryptionType: '0x17'
        TicketOptions: '0x40810000'
    condition: selection
level: high
tags:
    - attack.credential_access
    - attack.t1558.003
""",
    "dcsync": """
title: DCSync Attack
id: ddbbaacc-4444-5555-6666-777788880000
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            - '89e95b76-444d-4c62-991a-0facbeda640c'
    condition: selection
level: critical
tags:
    - attack.credential_access
    - attack.t1003.006
""",
    "wmi_persistence": """
title: WMI Event Subscription Persistence
id: eeddccbb-5555-6666-7777-888899991111
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID:
            - 19
            - 20
            - 21
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1546.003
""",
    "psexec_service": """
title: PsExec Service Installation
id: ffeeccbb-6666-7777-8888-999900002222
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\PSEXESVC.exe'
    condition: selection
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.002
""",
    "defender_disabled": """
title: Windows Defender Disabled
id: 11223344-7777-8888-9999-000011113333
logsource:
    product: windows
    service: windefend
detection:
    selection:
        EventID: 5001
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562.001
""",
    "wmi_remote_exec": """
title: WMI Remote Execution
id: 22334455-8888-9999-0000-111122224444
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\wmiprvse.exe'
        ParentImage|endswith: '\\svchost.exe'
        CommandLine|contains: 'wmic'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1047
""",
    "password_spraying": """
title: Password Spraying (Many 4625 from one IP)
id: 33445566-9999-0000-1111-222233335555
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    timeframe: 5m
    condition: selection | count() by IpAddress > 20
level: high
tags:
    - attack.credential_access
    - attack.t1110.003
""",
    "suspicious_service_creation": """
title: Suspicious Service Creation
id: 44556677-0000-1111-2222-333344446666
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ImagePath|contains:
            - 'Temp'
            - 'AppData'
            - 'ProgramData'
            - 'Users\\Public'
    condition: selection
level: critical
tags:
    - attack.persistence
    - attack.t1543.003
""",
    "linux_ld_preload": """
title: Linux LD_PRELOAD Persistence
id: 55667788-1111-2222-3333-444455557777
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains: 'LD_PRELOAD='
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1574.006
""",
    "linux_cron_modification": """
title: Cron Job Modification
id: 66778899-2222-3333-4444-555566668888
logsource:
    category: file_event
    product: linux
detection:
    selection:
        TargetFilename|startswith:
            - '/etc/cron'
            - '/var/spool/cron'
            - '/etc/crontab'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1053.003
""",
}


# ===========================================================================
# Hunt playbooks
# ===========================================================================

HUNT_PLAYBOOKS = {
    "initial-access": {
        "title": "Initial Access",
        "queries": [
            ("Phishing attachments",
             "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-"
             "Security';ID=4688} | Where-Object {$_.Message -match "
             "\"(doc|docm|xls|xlsm|htm|html|js|lnk)\"}"),
            ("Office spawning cmd/ps",
             "sysmon EventID 1 | where parent=winword.exe and "
             "process in (cmd.exe, powershell.exe, wscript.exe)"),
            ("Suspicious external connections",
             "sysmon EventID 3 | where destination not in "
             "(internal_ranges) and image in (winword.exe, excel.exe)"),
            ("LNK from mail client",
             "sysmon EventID 11 | where TargetFilename endswith '.lnk' "
             "and ParentImage endswith 'outlook.exe'"),
            ("ISO/IMG mount",
             "sysmon EventID 1 | where Image endswith 'mountvol.exe' "
             "or Image endswith 'Mount-DiskImage'"),
        ],
    },
    "execution": {
        "title": "Execution",
        "queries": [
            ("Rare processes",
             "sysmon EventID 1 | summarize count() by Image | "
             "where count_ < 5"),
            ("PowerShell from non-admin",
             "sysmon EventID 1 | where image=~'powershell.exe' and "
             "user_ not contains 'SYSTEM'"),
            ("Signed vs unsigned",
             "sysmon EventID 1 | where signature_status != 'Valid'"),
            ("Suspicious mshta/wscript",
             "sysmon EventID 1 | where Image endswith 'mshta.exe' "
             "or Image endswith 'wscript.exe'"),
            ("Rundll32 with URL",
             "sysmon EventID 1 | where Image endswith 'rundll32.exe' "
             "and CommandLine contains 'http'"),
        ],
    },
    "persistence": {
        "title": "Persistence",
        "queries": [
            ("Run keys modified",
             "sysmon EventID 13 | where TargetObject contains "
             "'CurrentVersion\\\\Run'"),
            ("New scheduled tasks",
             "Security EventID 4698"),
            ("New services",
             "System EventID 7045 | where ImagePath contains '.tmp' "
             "or ImagePath contains 'Temp'"),
            ("WMI persistence",
             "sysmon EventID 19,20,21"),
            ("Startup folder",
             "sysmon EventID 11 | where TargetFilename contains "
             "'\\Start Menu\\Programs\\Startup\\'"),
            ("BITS jobs",
             "sysmon EventID 1 | where Image endswith 'bitsadmin.exe'"),
        ],
    },
    "privilege-escalation": {
        "title": "Privilege Escalation",
        "queries": [
            ("SeDebugPrivilege",
             "Security EventID 4672 | where Privileges contains "
             "'SeDebugPrivilege'"),
            ("UAC bypass fodhelper",
             "sysmon EventID 1 | where parent in (fodhelper.exe, "
             "eventvwr.exe, sdclt.exe)"),
            ("Suspicious .dll sideloading",
             "sysmon EventID 7 | where Signed='false' and "
             "ImageLoaded contains 'Temp'"),
            ("Token impersonation",
             "sysmon EventID 1 | where Image endswith "
             "'PrintSpoofer.exe' or Image endswith 'RoguePotato.exe'"),
            ("SeImpersonate privilege",
             "Security EventID 4672 | where Privileges contains "
             "'SeImpersonatePrivilege'"),
        ],
    },
    "credential-access": {
        "title": "Credential Access",
        "queries": [
            ("LSASS access",
             "sysmon EventID 10 | where TargetImage endswith "
             "'lsass.exe' and GrantedAccess != '0x1000'"),
            ("SAM/SYSTEM dump",
             "sysmon EventID 11 | where TargetFilename contains "
             "('sam', 'system', 'security') and "
             "TargetFilename contains 'Temp'"),
            ("DCSync",
             "Security EventID 4662 | where Properties contains "
             "'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'"),
            ("Kerberoasting (RC4)",
             "Security EventID 4769 | where TicketEncryptionType=='0x17'"),
            ("AS-REP Roasting",
             "Security EventID 4768 | where PreAuthType=='0'"),
            ("Brute force (4625 flooding)",
             "Security EventID 4625 | summarize count() by IpAddress, "
             "TargetUserName | where count_ > 20"),
        ],
    },
    "lateral-movement": {
        "title": "Lateral Movement",
        "queries": [
            ("PsExec",
             "sysmon EventID 1 | where Image endswith 'PSEXESVC.exe'"),
            ("WMI remote",
             "sysmon EventID 1 | where Image endswith 'wmiprvse.exe' "
             "and ParentImage endswith 'svchost.exe'"),
            ("RDP logon",
             "Security EventID 4624 | where LogonType == 10"),
            ("Admin share access",
             "Security EventID 5140 | where ShareName contains '$'"),
            ("Pass-the-Hash (NTLM)",
             "Security EventID 4624 | where LogonType == 3 and "
             "AuthenticationPackageName == 'NTLM'"),
            ("WinRM",
             "sysmon EventID 1 | where ParentImage endswith "
             "'wsmprovhost.exe'"),
        ],
    },
    "defense-evasion": {
        "title": "Defense Evasion",
        "queries": [
            ("Event log cleared",
             "Security EventID 1102, 104"),
            ("AMSI bypass attempts",
             "sysmon EventID 1 | where CommandLine contains "
             "('amsi', 'amsiInitFailed', 'amsiContext')"),
            ("Timestomping",
             "sysmon EventID 2 | where CreationUtcTime != "
             "PreviousCreationUtcTime"),
            ("Disable Defender",
             "System EventID 7036 | where ServiceName contains "
             "'WinDefend' and Status == 'stopped'"),
            ("Firewall disabled",
             "Security EventID 4950"),
        ],
    },
    "command-control": {
        "title": "Command & Control",
        "queries": [
            ("Beaconing detection (long intervals)",
             "sysmon EventID 3 | summarize count() by "
             "DestinationIp, DestinationPort, bin(TimeGenerated, 5m)"),
            ("DNS tunneling (long queries)",
             "sysmon EventID 22 | where strlen(QueryName) > 50"),
            ("TLS to non-standard port",
             "sysmon EventID 3 | where DestinationPort !in (80, 443) "
             "and Protocol='tcp'"),
            ("Rare User-Agents",
             "proxy_logs | summarize count() by UserAgent | "
             "where count_ < 10"),
            ("Suspicious TLDs",
             "dns_logs | where QueryName matches regex "
             "'.*\\.(top|xyz|tk|ml|ga|cf)$'"),
        ],
    },
    "exfiltration": {
        "title": "Exfiltration",
        "queries": [
            ("Large outbound transfers",
             "netflow | summarize bytes=sum(Bytes) by "
             "SrcIp, DstIp | where bytes > 100MB"),
            ("Cloud uploads",
             "sysmon EventID 1 | where CommandLine contains "
             "('s3 cp', 'gsutil cp', 'aws s3', 'az storage')"),
            ("Archiving before exfil",
             "sysmon EventID 1 | where CommandLine contains "
             "('7z a', 'tar cz', 'zip -r', 'rar a')"),
            ("DNS tunneling",
             "sysmon EventID 22 | where strlen(QueryName) > 100"),
            ("Rclone usage",
             "sysmon EventID 1 | where Image endswith 'rclone.exe'"),
        ],
    },
    "impact": {
        "title": "Impact",
        "queries": [
            ("Mass file renames (ransomware)",
             "sysmon EventID 11 | summarize count() by "
             "TargetFilename_ext | where count_ > 1000"),
            ("Shadow copy deletion",
             "sysmon EventID 1 | where CommandLine contains "
             "'vssadmin delete shadows'"),
            ("Ransom note drops",
             "sysmon EventID 11 | where TargetFilename contains "
             "('README', 'DECRYPT', 'RECOVER')"),
            ("MBR overwrite",
             "sysmon EventID 9 | where TargetFilename contains "
             "'\\\\.\\PhysicalDrive'"),
        ],
    },
    "reconnaissance": {
        "title": "Reconnaissance",
        "queries": [
            ("Network scans",
             "sysmon EventID 3 | summarize count() by "
             "SourceIp, DestinationIp | where count_ > 100"),
            ("AD enumeration",
             "sysmon EventID 1 | where CommandLine contains "
             "('net group', 'net user /domain', 'nltest')"),
            ("BloodHound",
             "sysmon EventID 1 | where CommandLine contains "
             "'SharpHound' or CommandLine contains 'BloodHound'"),
            ("PowerView",
             "sysmon EventID 1 | where CommandLine contains "
             "'Get-NetUser' or CommandLine contains 'Get-DomainUser'"),
        ],
    },
}


# ===========================================================================
# MITRE ATT&CK mapping (расширено)
# ===========================================================================

MITRE_MAPPING = {
    "T1059.001": {"tactic": "execution", "name": "PowerShell",
                  "detect": "Sysmon 1 + script block logging 4104"},
    "T1059.003": {"tactic": "execution", "name": "Windows Command Shell",
                  "detect": "Sysmon 1 (cmd.exe)"},
    "T1059.005": {"tactic": "execution", "name": "Visual Basic",
                  "detect": "Sysmon 1 (cscript.exe, wscript.exe)"},
    "T1059.007": {"tactic": "execution", "name": "JavaScript",
                  "detect": "Sysmon 1 (mshta.exe, wscript.exe)"},
    "T1047": {"tactic": "execution", "name": "WMI",
              "detect": "Sysmon 1 (wmic.exe), 19/20/21"},
    "T1204.002": {"tactic": "execution", "name": "Malicious File",
                  "detect": "Sysmon 1 (office spawning shell)"},
    "T1053.005": {"tactic": "persistence", "name": "Scheduled Task",
                  "detect": "Security 4698, Sysmon 1 (schtasks.exe)"},
    "T1547.001": {"tactic": "persistence", "name": "Registry Run Keys",
                  "detect": "Sysmon 13 (CurrentVersion\\Run)"},
    "T1546.003": {"tactic": "persistence", "name": "WMI Event Subscription",
                  "detect": "Sysmon 19, 20, 21"},
    "T1543.003": {"tactic": "persistence", "name": "Windows Service",
                  "detect": "System 7045 (service install)"},
    "T1574.006": {"tactic": "persistence", "name": "LD_PRELOAD",
                  "detect": "Sysmon 1 (LD_PRELOAD env)"},
    "T1053.003": {"tactic": "persistence", "name": "Cron",
                  "detect": "File event /etc/cron*"},
    "T1003.001": {"tactic": "credential-access", "name": "LSASS Memory",
                  "detect": "Sysmon 10 (lsass.exe access)"},
    "T1003.003": {"tactic": "credential-access", "name": "NTDS",
                  "detect": "Sysmon 11 (ntds.dit in Temp)"},
    "T1003.006": {"tactic": "credential-access", "name": "DCSync",
                  "detect": "Security 4662 (DS-Replication-Get-Changes)"},
    "T1558.003": {"tactic": "credential-access", "name": "Kerberoasting",
                  "detect": "Security 4769 (RC4 TGS requests)"},
    "T1558.004": {"tactic": "credential-access", "name": "AS-REP Roasting",
                  "detect": "Security 4768 (PreAuthType=0)"},
    "T1110.003": {"tactic": "credential-access", "name": "Password Spraying",
                  "detect": "Security 4625 (flood from one IP)"},
    "T1550.002": {"tactic": "lateral-movement", "name": "Pass-the-Hash",
                  "detect": "Security 4624 (LogonType=3, NTLM)"},
    "T1021.001": {"tactic": "lateral-movement", "name": "RDP",
                  "detect": "Security 4624 (LogonType=10)"},
    "T1021.002": {"tactic": "lateral-movement", "name": "SMB/Admin Shares",
                  "detect": "Security 5140"},
    "T1021.006": {"tactic": "lateral-movement", "name": "WinRM",
                  "detect": "Sysmon 1 (wsmprovhost.exe parent)"},
    "T1562.001": {"tactic": "defense-evasion", "name": "Disable Tools",
                  "detect": "System 7036, Sysmon 1 (sc stop)"},
    "T1070.001": {"tactic": "defense-evasion", "name": "Clear Logs",
                  "detect": "Security 1102"},
    "T1070.006": {"tactic": "defense-evasion", "name": "Timestomp",
                  "detect": "Sysmon 2 (CreationUtcTime != PreviousCreationUtcTime)"},
    "T1562.004": {"tactic": "defense-evasion", "name": "Disable Firewall",
                  "detect": "Security 4950"},
    "T1140": {"tactic": "defense-evasion", "name": "Deobfuscate/Decode",
              "detect": "Sysmon 1 (certutil -decode)"},
    "T1071.001": {"tactic": "command-and-control", "name": "Web Protocols",
                  "detect": "Sysmon 3 (periodic HTTP)"},
    "T1071.004": {"tactic": "command-and-control", "name": "DNS",
                  "detect": "Sysmon 22 (long DNS queries)"},
    "T1571": {"tactic": "command-and-control", "name": "Non-Standard Port",
              "detect": "Sysmon 3 (TLS on non-443 port)"},
    "T1048.003": {"tactic": "exfiltration", "name": "Exfil Over Unencrypted",
                  "detect": "Sysmon 22 (DNS tunnel)"},
    "T1567.002": {"tactic": "exfiltration", "name": "Cloud Storage",
                  "detect": "Sysmon 1 (s3/gsutil/rclone)"},
    "T1486": {"tactic": "impact", "name": "Data Encrypted",
              "detect": "Sysmon 11 (mass file renames), 1 (vssadmin)"},
    "T1490": {"tactic": "impact", "name": "Inhibit System Recovery",
              "detect": "Sysmon 1 (vssadmin delete shadows)"},
    "T1485": {"tactic": "impact", "name": "Data Destruction",
              "detect": "Sysmon 1 (cipher /w, sdelete)"},
    "T1087": {"tactic": "reconnaissance", "name": "Account Discovery",
              "detect": "Sysmon 1 (net user /domain)"},
    "T1082": {"tactic": "discovery", "name": "System Info Discovery",
              "detect": "Sysmon 1 (systeminfo.exe, hostname)"},
    "T1046": {"tactic": "discovery", "name": "Network Service Discovery",
              "detect": "Sysmon 3 (mass connections)"},
}


# ===========================================================================
# Display
# ===========================================================================

def show_sigma() -> None:
    t = Table(title=f"📜 Sigma rules ({len(SIGMA_RULES)})")
    t.add_column("#", width=4)
    t.add_column("Rule", style="cyan")
    t.add_column("Description", style="white", max_width=60)
    for i, (name, content) in enumerate(SIGMA_RULES.items(), 1):
        title = ""
        for line in content.splitlines():
            if line.startswith("title:"):
                title = line.replace("title:", "").strip()
                break
        t.add_row(str(i), name, title)
    console.print(t)

    choice = Prompt.ask("Показать правило (Enter = нет)",
                        default="").strip()
    if choice and choice in SIGMA_RULES:
        console.print(f"\n[bold cyan]═══ Sigma: {choice} ═══[/bold cyan]\n")
        console.print(SIGMA_RULES[choice])
        # Finding — Sigma просмотрена
        _save_finding(THFinding(
            kind="sigma_reviewed",
            severity="high",
            title=f"Sigma rule: {choice}",
            target="threat_hunting",
            evidence=SIGMA_RULES[choice][:500],
            data={"rule": choice},
        ))


def show_playbooks() -> None:
    t = Table(title=f"🎯 Hunt playbooks ({len(HUNT_PLAYBOOKS)})")
    t.add_column("#", width=4)
    t.add_column("Tactic", style="cyan")
    t.add_column("Queries", style="green", width=8)
    for i, (key, data) in enumerate(HUNT_PLAYBOOKS.items(), 1):
        t.add_row(str(i), data["title"], str(len(data["queries"])))
    console.print(t)

    choice = Prompt.ask("Какую тактику показать? (Enter = нет)",
                        default="").strip()
    if choice:
        if choice.isdigit() and 1 <= int(choice) <= len(HUNT_PLAYBOOKS):
            key = list(HUNT_PLAYBOOKS.keys())[int(choice) - 1]
        else:
            key = choice
        _show_playbook(key)


def _show_playbook(key: str) -> None:
    pb = HUNT_PLAYBOOKS.get(key)
    if not pb:
        console.print(f"[red]Не найден: {key}[/red]")
        return
    console.print(f"\n[bold cyan]═══ {pb['title']} ═══[/bold cyan]\n")
    for title, query in pb["queries"]:
        t = Table(title=f"[bold green]{title}[/bold green]",
                  show_header=False, border_style="dim")
        t.add_column("Query")
        for line in query.split("\n"):
            t.add_row(f"[cyan]{line}[/cyan]")
        console.print(t)
    # Finding
    _save_finding(THFinding(
        kind="playbook_opened",
        severity="high",
        title=f"Hunt playbook: {pb['title']}",
        target=f"tactic:{key}",
        evidence=f"{len(pb['queries'])} queries",
        data={"tactic": key, "queries": len(pb["queries"])},
    ))


def show_mitre() -> None:
    t = Table(title=f"🗺  MITRE ATT&CK mapping ({len(MITRE_MAPPING)})")
    t.add_column("TTP", style="cyan", width=12)
    t.add_column("Tactic", style="magenta", width=20)
    t.add_column("Name", style="white", width=28)
    t.add_column("Detection", style="green", max_width=45)
    for ttp, data in MITRE_MAPPING.items():
        t.add_row(ttp, data["tactic"], data["name"], data["detect"][:45])
    console.print(t)


# ===========================================================================
# Экспорт
# ===========================================================================

def export_sigma_dir(out_dir: str | None = None) -> Path:
    """Сохранить все Sigma rules в YAML-файлы."""
    if not out_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = str(HUNT_DIR / f"sigma_rules_{ts}")
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    count = 0
    for name, content in SIGMA_RULES.items():
        try:
            (d / f"{name}.yml").write_text(content.strip() + "\n",
                                              encoding="utf-8")
            count += 1
        except Exception as exc:
            log.warning("sigma write %s: %s", name, exc)
    console.print(f"[green]✓ {count} Sigma rules → {d}[/green]")
    db.save_scan("hunting_sigma_export", str(d), {"count": count})
    return d


def export_playbooks_md(out_path: str | None = None) -> Path | None:
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(HUNT_DIR / f"playbooks_{ts}.md")
    lines = [
        "# Hunt Playbooks",
        f"_Generated: {datetime.now().isoformat()}_",
        "",
    ]
    for key, pb in HUNT_PLAYBOOKS.items():
        lines.append(f"## {pb['title']} (`{key}`)")
        lines.append("")
        for title, query in pb["queries"]:
            lines.append(f"### {title}")
            lines.append("```")
            lines.append(query)
            lines.append("```")
            lines.append("")
    try:
        Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Playbooks MD: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]MD: {exc}[/red]")
        return None


def export_playbooks_html(out_path: str | None = None) -> Path | None:
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(HUNT_DIR / f"playbooks_{ts}.html")
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Hunt Playbooks</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;max-width:1200px;margin:0 auto;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:32px;}",
        "h3{color:#7ad9ff;margin-top:18px;}",
        "pre{background:#111;border:1px solid #222;border-radius:6px;"
        "padding:10px;overflow-x:auto;color:#a0ffa0;font-size:12px;}",
        "</style></head><body>",
        f"<h1>🎯 Hunt Playbooks ({len(HUNT_PLAYBOOKS)})</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
    ]
    for key, pb in HUNT_PLAYBOOKS.items():
        parts.append(f"<h2>{html_mod.escape(pb['title'])} "
                     f"<small>(<code>{html_mod.escape(key)}</code>)</small>"
                     f"</h2>")
        for title, query in pb["queries"]:
            parts.append(f"<h3>{html_mod.escape(title)}</h3>")
            parts.append(f"<pre>{html_mod.escape(query)}</pre>")
    parts.append("</body></html>")
    try:
        Path(out_path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ Playbooks HTML: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]HTML: {exc}[/red]")
        return None


def export_mitre_navigator(out_path: str | None = None) -> Path | None:
    """Экспорт в формате MITRE ATT&CK Navigator layer."""
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(HUNT_DIR / f"navigator_layer_{ts}.json")

    techniques = []
    for ttp_id, data in MITRE_MAPPING.items():
        # Tactic → shortname
        tactic_short = data["tactic"].replace("_", "-")
        techniques.append({
            "techniqueID": ttp_id,
            "tactic": tactic_short,
            "color": "#00ff9c",
            "comment": f"{data['name']} — {data['detect']}",
            "enabled": True,
            "score": 1,
        })
    layer = {
        "name": "CyberSec Toolkit — Hunted TTPs",
        "versions": {"attack": "14", "navigator": "4.9.0",
                     "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "TTPs с детект-рекомендациями",
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#00ff9c", "#ffd23f", "#ff2020"],
                     "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "Hunted TTP", "color": "#00ff9c"}
        ],
        "metadata": [
            {"name": "Generated by", "value": "CyberSec Toolkit"},
            {"name": "Date", "value": datetime.now().isoformat()},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#0a0a0a",
        "selectTechniquesAcrossTactics": True,
    }
    try:
        Path(out_path).write_text(
            json.dumps(layer, indent=2, ensure_ascii=False),
            encoding="utf-8")
        console.print(f"[green]✓ Navigator layer: {out_path}[/green]")
        console.print("[dim]→ загрузи в https://mitre-attack.github.io/"
                      "attack-navigator/[/dim]")
        db.save_scan("hunting_navigator", "layer",
                     {"path": str(out_path),
                      "techniques": len(techniques)})
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]Navigator: {exc}[/red]")
        return None


def export_mitre_csv(out_path: str | None = None) -> Path | None:
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(HUNT_DIR / f"mitre_{ts}.csv")
    try:
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ttp_id", "tactic", "name", "detection"])
            for ttp, data in MITRE_MAPPING.items():
                w.writerow([ttp, data["tactic"], data["name"],
                            data["detect"]])
        console.print(f"[green]✓ MITRE CSV: {out_path}[/green]")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_dashboard(out_path: str | None = None) -> Path | None:
    """Полный HTML-дашборд (rules + playbooks + MITRE)."""
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(HUNT_DIR / f"dashboard_{ts}.html")

    parts = [
        "<!DOCTYPE html><html lang='ru'><head>"
        "<meta charset='utf-8'>",
        "<title>Threat Hunting Dashboard</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;max-width:1300px;margin:0 auto;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:32px;}",
        "h3{color:#7ad9ff;margin-top:18px;}",
        ".kpi-grid{display:grid;"
        "grid-template-columns:repeat(auto-fit,minmax(150px,1fr));"
        "gap:12px;margin:16px 0;}",
        ".kpi{background:#111;border:1px solid #222;border-radius:6px;"
        "padding:14px;text-align:center;}",
        ".kpi .v{font-size:24px;color:#00ff9c;font-weight:bold;}",
        ".kpi .l{font-size:11px;color:#888;"
        "text-transform:uppercase;}",
        "pre{background:#111;border:1px solid #222;border-radius:6px;"
        "padding:10px;overflow-x:auto;color:#a0ffa0;font-size:12px;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:6px;"
        "text-align:left;border:1px solid #222;}",
        "td{padding:5px 8px;border:1px solid #222;}"
        "tr:nth-child(even){background:#0d0d0d;}",
        ".toc a{color:#7ad9ff;text-decoration:none;margin-right:12px;}",
        ".toc a:hover{color:#00ff9c;}",
        "</style></head><body>",
        "<h1>🎯 Threat Hunting Dashboard</h1>",
        f"<p>Generated: "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<div class='kpi-grid'>",
        f"<div class='kpi'><div class='v'>{len(SIGMA_RULES)}</div>"
        f"<div class='l'>Sigma rules</div></div>",
        f"<div class='kpi'><div class='v'>{len(HUNT_PLAYBOOKS)}</div>"
        f"<div class='l'>Playbooks</div></div>",
        f"<div class='kpi'><div class='v'>{len(MITRE_MAPPING)}</div>"
        f"<div class='l'>MITRE TTPs</div></div>",
        "</div>",
        "<div class='toc'>",
        "<a href='#sigma'>Sigma rules</a>",
        "<a href='#playbooks'>Playbooks</a>",
        "<a href='#mitre'>MITRE ATT&amp;CK</a>",
        "</div>",
        "<h2 id='sigma'>📜 Sigma rules</h2>",
    ]
    for name, content in SIGMA_RULES.items():
        parts.append(f"<h3>{html_mod.escape(name)}</h3>")
        parts.append(f"<pre>{html_mod.escape(content.strip())}</pre>")

    parts.append("<h2 id='playbooks'>🎯 Hunt Playbooks</h2>")
    for key, pb in HUNT_PLAYBOOKS.items():
        parts.append(f"<h3>{html_mod.escape(pb['title'])} "
                     f"(<code>{html_mod.escape(key)}</code>)</h3>")
        for title, query in pb["queries"]:
            parts.append(f"<strong>{html_mod.escape(title)}</strong>")
            parts.append(f"<pre>{html_mod.escape(query)}</pre>")

    parts.append("<h2 id='mitre'>🗺  MITRE ATT&amp;CK mapping</h2>")
    parts.append("<table><tr><th>TTP</th><th>Tactic</th>"
                 "<th>Name</th><th>Detection</th></tr>")
    for ttp, data in MITRE_MAPPING.items():
        parts.append(
            f"<tr><td><code>{html_mod.escape(ttp)}</code></td>"
            f"<td>{html_mod.escape(data['tactic'])}</td>"
            f"<td>{html_mod.escape(data['name'])}</td>"
            f"<td>{html_mod.escape(data['detect'])}</td></tr>")
    parts.append("</table></body></html>")

    try:
        Path(out_path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ Dashboard: {out_path}[/green]")
        db.save_scan("hunting_dashboard", "dashboard",
                     {"path": str(out_path),
                      "sigma": len(SIGMA_RULES),
                      "playbooks": len(HUNT_PLAYBOOKS),
                      "mitre": len(MITRE_MAPPING)})
        _notify("🎯 Hunting dashboard",
                f"Sigma: {len(SIGMA_RULES)}, "
                f"Playbooks: {len(HUNT_PLAYBOOKS)}, "
                f"TTPs: {len(MITRE_MAPPING)}",
                severity="medium")
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]Dashboard: {exc}[/red]")
        return None


# ===========================================================================
# CLI
# ===========================================================================

def cli_sigma() -> None:
    show_sigma()


def cli_playbooks() -> None:
    show_playbooks()


def cli_playbook(tactic: str) -> None:
    _show_playbook(tactic)


def cli_mitre() -> None:
    show_mitre()


def cli_export_sigma() -> None:
    export_sigma_dir()


def cli_export_dashboard() -> None:
    export_dashboard()


def cli_export_navigator() -> None:
    export_mitre_navigator()


def menu() -> None:
    t = Table(title="[bold]🎯 Threat Hunting (extended)[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", f"Sigma rules ({len(SIGMA_RULES)} примеров)"),
        ("2", f"Hunt playbooks ({len(HUNT_PLAYBOOKS)} тактик)"),
        ("3", "Playbook по конкретной тактике"),
        ("4", f"MITRE ATT&CK mapping ({len(MITRE_MAPPING)} TTPs)"),
        ("5", "Экспорт Sigma rules → YAML-файлы"),
        ("6", "Экспорт playbooks (Markdown)"),
        ("7", "Экспорт playbooks (HTML)"),
        ("8", "Экспорт MITRE Navigator layer (JSON)"),
        ("9", "Экспорт MITRE (CSV)"),
        ("10", "Полный HTML-дашборд"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного IR / hunting.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        show_sigma()
    elif c == "2":
        show_playbooks()
    elif c == "3":
        tactic = Prompt.ask("Тактика",
                            choices=list(HUNT_PLAYBOOKS.keys()),
                            default="execution")
        _show_playbook(tactic)
    elif c == "4":
        show_mitre()
    elif c == "5":
        export_sigma_dir()
    elif c == "6":
        export_playbooks_md()
    elif c == "7":
        export_playbooks_html()
    elif c == "8":
        export_mitre_navigator()
    elif c == "9":
        export_mitre_csv()
    elif c == "10":
        p = export_dashboard()
        if p and Confirm.ask("Открыть в браузере?", default=False):
            import os
            import sys
            if sys.platform == "win32":
                os.startfile(str(p))
            elif sys.platform == "darwin":
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}" >/dev/null 2>&1 &')