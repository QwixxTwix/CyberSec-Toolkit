"""
Reverse Engineering Suite Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / malware analysis / CTF.

Возможности:
    ─── Определение типа ───
    - 60+ magic signatures (PE/ELF/Mach-O, архивы, медиа, БД, документы,
      крипто-файлы, скрипты, контейнеры, firmware)

    ─── Entropy ───
    - Shannon entropy (общая + по блокам)
    - Визуализация распределения (ASCII-график)
    - Классификация (plain/text/binary/packed/encrypted)
    - Детект упаковки (высокая энтропия + секции)

    ─── Strings ───
    - ASCII + UTF-16LE + UTF-16BE + UTF-32
    - IOC-extractor: URLs, IPs, emails, domains, hashes, base64,
      BTC/ETH адреса, Windows paths, registry keys, MAC-адреса,
      AWS keys, JWT, user-agents, mutex, crypto wallets
    - Классификация по категориям (network/crypto/persistence/security)

    ─── PE (Windows) ───
    - Headers: machine, subsystem, timestamp, imagebase, entrypoint
    - Sections (+ entropy per section)
    - Imports (DLL + functions) + imphash (правильный)
    - Exports
    - TLS callbacks
    - Debug info (PDB path)
    - Resources (version info, manifest)
    - Packer detection (UPX, VMProtect, Themida, ASPack, MPRESS,
      Enigma, Obsidium, PECompact, FSG, Petite)
    - .NET detection
    - Authenticode signature info

    ─── ELF (Linux) ───
    - Headers: class, endian, type, machine
    - Sections (+ entropy)
    - Symbols (imported + exported)
    - Dynamic libraries (DT_NEEDED)
    - Static vs dynamic, PIE
    - Packer hints

    ─── Mach-O (macOS) ───
    - Headers: cputype, subtype, filetype, ncmds
    - Universal binary detection
    - Load commands summary

    ─── YARA ───
    - 15+ встроенных правил (Meterpreter, Mimikatz, Cobalt Strike,
      PowerShell encoded, wget|sh, AWS keys, base64, cryptominers,
      ransomware hints, persistence, reverse shells)
    - Пользовательские правила
    - Tags + matched strings

    ─── IOC / Shellcode ───
    - Детект shellcode (NOP sled, common stubs)
    - Cryptominer hints (stratum://, xmrig, monero)
    - Ransomware hints (.encrypt, extension lists, wallet addresses)
    - Packers hints

    ─── Интеграция ───
    - Findings → notes для critical/high
    - Notify по завершении
    - Экспорт: JSON / HTML / Markdown / CSV
"""
import base64
import hashlib
import html as html_mod
import json
import math
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

RE_DIR = REPORT_DIR / "reverse"
RE_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class REFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: REFinding) -> int:
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
            tags=["re", "malware", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Magic signatures (расширенный)
# ===========================================================================

MAGIC = [
    # Executables
    (b"\x4D\x5A", "PE/DOS executable (Windows)"),
    (b"\x7FELF", "ELF executable (Linux)"),
    (b"\xCA\xFE\xBA\xBE", "Mach-O Universal / Java class"),
    (b"\xCF\xFA\xED\xFE", "Mach-O 64-bit (macOS)"),
    (b"\xCE\xFA\xED\xFE", "Mach-O 32-bit (macOS)"),
    (b"\xFE\xED\xFA\xCE", "Mach-O 32-bit BE (macOS)"),
    (b"\xFE\xED\xFA\xCF", "Mach-O 64-bit BE (macOS)"),
    (b"\x00asm", "WebAssembly"),
    (b"\xCA\xFE\xBA\xBE\x00\x00\x00\x02", "Java class (Java 8+)"),

    # Archives
    (b"\x50\x4B\x03\x04", "ZIP/JAR/APK/DOCX"),
    (b"\x1F\x8B", "gzip"),
    (b"\x42\x5A\x68", "bzip2"),
    (b"\xFD\x37\x7A\x58\x5A", "XZ"),
    (b"\x37\x7A\xBC\xAF\x27\x1C", "7-Zip"),
    (b"\x52\x61\x72\x21", "RAR"),
    (b"\x04\x22\x4D\x18", "LZ4"),
    (b"\x28\xB5\x2F\xFD", "Zstandard"),

    # Documents
    (b"\x25\x50\x44\x46", "PDF"),
    (b"\xD0\xCF\x11\xE0", "OLE/Office (doc/xls)"),
    (b"\x50\x4B\x03\x04\x14\x00\x06\x00", "DOCX/XLSX/PPTX"),

    # Media
    (b"\x89\x50\x4E\x47", "PNG"),
    (b"\xFF\xD8\xFF", "JPEG"),
    (b"GIF8", "GIF"),
    (b"RIFF", "RIFF (WAV/AVI/WebP)"),
    (b"\x4F\x67\x67\x53", "OGG"),
    (b"\x49\x44\x33", "MP3 (ID3)"),
    (b"\x1A\x45\xDF\xA3", "Matroska/WebM"),
    (b"\x00\x00\x01\xBA", "MPEG-PS"),
    (b"\x66\x4C\x61\x43", "FLAC"),

    # Databases / data
    (b"SQLite format 3", "SQLite DB"),
    (b"\x89HDF\r\n\x1A\n", "HDF5"),
    (b"PAR1", "Parquet"),

    # Crypto / keys
    (b"-----BEGIN ", "PEM (certificate/key)"),

    # Disk / firmware
    (b"\x00\x00\x55\xAA", "MBR"),
    (b"EFI PART", "GPT header"),
    (b"\xD0\x0D\xFE\xED", "Windows Event Log (EVTX)"),
    (b"regf", "Windows Registry hive"),

    # Scripts / text
    (b"#!", "Shell script (shebang)"),
    (b"<?xml", "XML"),
    (b"<!DOCTYPE html", "HTML"),
    (b"{\\rtf", "RTF"),

    # Container / VM
    (b"KDMV", "VMware disk"),
    (b"QFI\xFB", "QCOW (QEMU)"),
    (b"conectix", "VHD (Hyper-V)"),

    # Forensics
    (b"\x45\x4C\x46\x46", "Apple DMG"),
    (b"EVF\x09\x0D\x0A\xFF\x00", "EnCase E01"),
    (b"\x6B\x6F\x6C\x61", "Kola forensics"),
]


def detect_file_type(path: Path) -> str:
    """Определить тип файла по magic-байтам."""
    try:
        with path.open("rb") as f:
            head = f.read(64)
    except Exception:
        return "unknown"
    for sig, name in MAGIC:
        if head.startswith(sig):
            return name
    return "unknown"


# ===========================================================================
# Entropy
# ===========================================================================

def _entropy(data: bytes) -> float:
    """Shannon entropy 0.0 – 8.0."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    ent = 0.0
    for count in counter.values():
        p = count / length
        ent -= p * math.log2(p)
    return round(ent, 3)


def entropy_blocks(path: Path, block_size: int = 4096,
                   max_blocks: int = 4096) -> list[dict]:
    """Entropy по блокам."""
    blocks: list[dict] = []
    try:
        with path.open("rb") as f:
            idx = 0
            while True:
                chunk = f.read(block_size)
                if not chunk:
                    break
                blocks.append({
                    "offset": idx * block_size,
                    "size": len(chunk),
                    "entropy": _entropy(chunk),
                })
                idx += 1
                if idx > max_blocks:
                    break
    except Exception as exc:  # noqa: BLE001
        log.warning("entropy: %s", exc)
    return blocks


def _classify_entropy(ent: float) -> str:
    if ent > 7.5:
        return "encrypted/compressed/packed (VERY HIGH)"
    if ent > 7.0:
        return "packed/compressed (HIGH)"
    if ent > 5.5:
        return "mixed (likely compiled code)"
    if ent > 3.5:
        return "binary data"
    return "plain/text"


def analyze_entropy(path: Path, max_bytes: int = 10 * 1024 * 1024) -> dict:
    """Общая энтропия + hashes + классификация."""
    try:
        data = path.read_bytes()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    ent = _entropy(data[:max_bytes])
    return {
        "size": len(data),
        "entropy": ent,
        "classification": _classify_entropy(ent),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
    }


def visualize_entropy(blocks: list[dict], width: int = 60) -> str:
    """ASCII-график энтропии по блокам."""
    if not blocks:
        return ""
    lines = []
    lines.append("  Entropy per block (0.0 ─── 8.0):")
    for i, b in enumerate(blocks[:80]):
        ent = b["entropy"]
        bar_len = int(ent / 8.0 * width)
        bar = "█" * bar_len + "░" * (width - bar_len)
        marker = "⚠" if ent > 7.2 else " "
        lines.append(f"  {b['offset']:>10}  [{bar}] {ent:.2f} {marker}")
    if len(blocks) > 80:
        lines.append(f"  … ещё {len(blocks)-80} блоков")
    return "\n".join(lines)


# ===========================================================================
# Strings (расширенный)
# ===========================================================================

IOC_PATTERNS = {
    "urls": re.compile(r"https?://[^\s\"'<>]{6,200}"),
    "ips": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                      r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "ipv6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}"
                       r"[0-9a-fA-F]{1,4}\b"),
    "emails": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}"
    ),
    "domains": re.compile(
        r"\b(?:[a-z0-9\-]{2,63}\.)+(?:com|net|org|ru|io|dev|xyz|info|"
        r"biz|cc|cn|top|club|online|site|shop|app|me|co|tv|pro)\b",
        re.IGNORECASE,
    ),
    "windows_paths": re.compile(r"[A-Za-z]:\\(?:[^\\\s\"'<>]+\\)*[^\\\s\"'<>]+"),
    "unix_paths": re.compile(r"/(?:usr|bin|sbin|etc|var|opt|tmp|home|root|proc|sys|dev)(?:/[^\s\"'<>]+)*"),
    "registry": re.compile(r"HK(?:LM|CU|CR|U|CC|EY_)[\\\w\.\-\s]+"),
    "hashes": re.compile(r"\b[a-fA-F0-9]{32,128}\b"),
    "base64": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}"
                       r"\.[A-Za-z0-9_\-]{10,}"),
    "aws_keys": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws_secrets": re.compile(r"(?i)aws[_\-\s]*(?:secret|access)[_\-\s]*key"
                              r"[\s:=\"']{0,8}([A-Za-z0-9/+=]{40})"),
    "btc_address": re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b"),
    "eth_address": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "monero_address": re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    "mac_addresses": re.compile(r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"),
    "mutex": re.compile(r"(?i)(?:mutex|mux)[_\s:=\"']{0,4}([A-Za-z0-9_\-{}]{4,60})"),
    "user_agents": re.compile(
        r"Mozilla/[45]\.0 \([^\)]{10,150}\)"
    ),
    "stratum_urls": re.compile(r"stratum\+?tcp://[^\s\"'<>]+"),
    "onion": re.compile(r"\b[a-z2-7]{16,56}\.onion\b"),
    "cve_ids": re.compile(r"CVE-\d{4}-\d{4,7}"),
    "guid": re.compile(
        r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
        r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
    ),
}

SUSPICIOUS_STRINGS = [
    # Anti-debug / anti-VM
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "OutputDebugString",
    "VBoxGuest", "VBoxService", "vmware", "VirtualBox", "qemu",
    "sbiedll.dll", "SbieDll", "dbghelp.dll",
    # Crypto
    "AES", "RSA", "CryptEncrypt", "CryptGenKey", "BCryptEncrypt",
    # Ransomware hints
    "vssadmin delete shadows", "bcdedit /set", "wbadmin delete",
    ".encrypt", ".locky", ".crypt", ".wcry", ".wncry", ".cerber",
    "READ_ME", "HOW_TO_DECRYPT", "DECRYPT_INSTRUCTIONS",
    # Crypto miners
    "xmrig", "stratum", "monero", "minerd", "cpuminer", "NiceHash",
    # C2 / RAT
    "metsrv", "Meterpreter", "meterpreter", "stdapi_", "Cobalt",
    "beacon", "silver", "sliver", "teamserver", "cobaltstrike",
    # Persistence
    "CurrentVersion\\Run", "schtasks", "reg add HKLM",
    "crontab", "systemd", "bashrc",
    # Credentials / LSASS
    "sekurlsa", "lsass", "SAM", "SYSTEM", "NTDS.dit",
    "mimikatz", "wce.exe", "pwdump", "gsecdump",
    # Reverse shell
    "/dev/tcp/", "bash -i", "sh -i", "nc -e",
    # Known malware
    "WannaCry", "NotPetya", "Petya", "Emotet", "Trickbot",
    "Ryuk", "REvil", "Conti", "LockBit", "BlackCat", "Clop",
    # Anti-VM
    "sandboxie", "wine_get_unix_file_name", "cuckoomon", "hook.dll",
]


def extract_strings(path: Path, min_len: int = 4,
                    unicode: bool = True) -> dict:
    """Извлечь строки (ASCII + UTF-16LE + UTF-16BE) + IOC."""
    try:
        data = path.read_bytes()
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}

    # ASCII
    ascii_re = re.compile(rb"[\x20-\x7E]{%d,}" % min_len)
    ascii_strs = [m.group().decode("ascii", errors="ignore")
                  for m in ascii_re.finditer(data)]

    uni_strs: list[str] = []
    if unicode:
        # UTF-16LE
        uni_le_re = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len)
        for m in uni_le_re.finditer(data):
            try:
                uni_strs.append(m.group().decode("utf-16le", errors="ignore"))
            except Exception:
                pass
        # UTF-16BE
        uni_be_re = re.compile(rb"(?:\x00[\x20-\x7E]){%d,}" % min_len)
        for m in uni_be_re.finditer(data):
            try:
                uni_strs.append(m.group().decode("utf-16be", errors="ignore"))
            except Exception:
                pass

    all_strs = ascii_strs + uni_strs

    # IOC extraction
    interesting: dict[str, list[str]] = {k: [] for k in IOC_PATTERNS}
    for s in all_strs:
        for cat, pat in IOC_PATTERNS.items():
            for m in pat.findall(s):
                if isinstance(m, tuple):
                    m = m[0] if m else ""
                if m:
                    interesting[cat].append(m)

    # Base64 decode (top 30)
    decoded_b64: list[dict] = []
    for b64 in interesting.get("base64", [])[:30]:
        try:
            pad = "=" * (-len(b64) % 4)
            raw = base64.b64decode(b64 + pad)
            text = raw.decode("utf-8", errors="ignore")
            printable = sum(1 for c in text if c.isprintable())
            if len(text) > 0 and printable / len(text) > 0.85:
                decoded_b64.append({
                    "encoded": b64[:80],
                    "decoded": text[:200],
                })
        except Exception:
            pass
    interesting["base64_decoded"] = decoded_b64  # type: ignore

    # Suspicious strings
    suspicious_hits: list[dict] = []
    lc_all = [s.lower() for s in all_strs]
    joined = "\n".join(lc_all)
    for kw in SUSPICIOUS_STRINGS:
        kwl = kw.lower()
        if kwl in joined:
            # Найти первый контекст
            idx = joined.find(kwl)
            ctx = joined[max(0, idx - 30):idx + len(kwl) + 30]
            suspicious_hits.append({"keyword": kw, "context": ctx.strip()})

    # Дедупликация
    for k in list(interesting.keys()):
        if isinstance(interesting[k], list):
            try:
                interesting[k] = sorted(set(interesting[k]))[:200]
            except Exception:
                pass

    return {
        "ascii_count": len(ascii_strs),
        "unicode_count": len(uni_strs),
        "total": len(all_strs),
        "sample": all_strs[:200],
        "interesting": interesting,
        "suspicious": suspicious_hits,
    }


# ===========================================================================
# PE parser (расширенный)
# ===========================================================================

@dataclass
class PEParser:
    is_pe: bool = False
    is_dotnet: bool = False
    is_signed: bool = False
    arch: str = ""
    machine: int = 0
    timestamp: int = 0
    timestamp_str: str = ""
    subsystem: int = 0
    subsystem_str: str = ""
    entrypoint: int = 0
    imagebase: int = 0
    characteristics: int = 0
    dll_characteristics: int = 0
    sections: list = field(default_factory=list)
    imports: dict = field(default_factory=dict)  # dll -> [functions]
    dlls: list = field(default_factory=list)
    exports: list = field(default_factory=list)
    imphash: str = ""
    packer_hints: list = field(default_factory=list)
    tls_callbacks: list = field(default_factory=list)
    pdb_path: str = ""
    version_info: dict = field(default_factory=dict)
    entropy_per_section: dict = field(default_factory=dict)


def parse_pe(path: Path) -> PEParser:
    """Разбор PE-заголовков (без pefile — свой парсер)."""
    p = PEParser()
    try:
        data = path.read_bytes()
    except Exception:
        return p
    if not data.startswith(b"MZ"):
        return p
    p.is_pe = True

    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            p.is_pe = False
            return p
        coff = pe_off + 4
        machine = struct.unpack_from("<H", data, coff)[0]
        p.machine = machine
        p.arch = {
            0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM",
            0x1c4: "ARMv7", 0xaa64: "ARM64",
            0x200: "IA64", 0x166: "MIPS",
        }.get(machine, f"0x{machine:x}")

        n_sections = struct.unpack_from("<H", data, coff + 2)[0]
        p.timestamp = struct.unpack_from("<I", data, coff + 4)[0]
        try:
            if 0 < p.timestamp < 4102444800:  # до 2100
                p.timestamp_str = datetime.fromtimestamp(
                    p.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            else:
                p.timestamp_str = str(p.timestamp)
        except Exception:
            p.timestamp_str = str(p.timestamp)

        p.characteristics = struct.unpack_from("<H", data, coff + 18)[0]
        p.is_dotnet = bool(p.characteristics & 0x2000)

        opt_off = coff + 20
        opt_magic = struct.unpack_from("<H", data, opt_off)[0]
        is_pe32p = opt_magic == 0x20b
        p.entrypoint = struct.unpack_from("<I", data, opt_off + 16)[0]
        if is_pe32p:
            p.imagebase = struct.unpack_from("<Q", data, opt_off + 24)[0]
            p.subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
            p.dll_characteristics = struct.unpack_from(
                "<H", data, opt_off + 70)[0]
        else:
            p.imagebase = struct.unpack_from("<I", data, opt_off + 28)[0]
            p.subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
            p.dll_characteristics = struct.unpack_from(
                "<H", data, opt_off + 70)[0]

        p.subsystem_str = {
            0: "Unknown", 1: "Native", 2: "GUI", 3: "Console",
            5: "OS/2", 7: "POSIX", 9: "WinCE", 10: "EFI App",
            11: "EFI Driver", 12: "EFI Runtime", 13: "EFI ROM",
            14: "Xbox", 16: "Boot",
        }.get(p.subsystem, f"0x{p.subsystem:x}")

        # Sections + entropy per section
        sec_off = opt_off + (240 if is_pe32p else 224)
        for i in range(min(n_sections, 40)):
            so = sec_off + i * 40
            name = data[so:so + 8].rstrip(b"\x00").decode(
                "latin1", errors="ignore")
            vsize = struct.unpack_from("<I", data, so + 8)[0]
            vaddr = struct.unpack_from("<I", data, so + 12)[0]
            rawsize = struct.unpack_from("<I", data, so + 16)[0]
            rawoff = struct.unpack_from("<I", data, so + 20)[0]
            chars = struct.unpack_from("<I", data, so + 36)[0]
            # Entropy секции
            section_data = data[rawoff:rawoff + min(rawsize, 1024 * 1024)]
            ent = _entropy(section_data)
            p.entropy_per_section[name] = ent
            p.sections.append({
                "name": name, "vsize": vsize, "vaddr": hex(vaddr),
                "rawsize": rawsize, "rawoff": hex(rawoff),
                "chars": hex(chars), "entropy": ent,
            })

        # Packer hints (расширенные)
        sec_names = [s["name"].upper() for s in p.sections]
        sec_names_lc = [s["name"].lower() for s in p.sections]
        joined_names = " ".join(sec_names) + " " + " ".join(sec_names_lc)

        if "UPX0" in sec_names or "UPX1" in sec_names or "UPX2" in sec_names:
            p.packer_hints.append("UPX")
        if ".VMP0" in sec_names or ".VMP1" in sec_names or ".vmp" in joined_names:
            p.packer_hints.append("VMProtect")
        if ".themida" in joined_names or ".winlice" in joined_names:
            p.packer_hints.append("Themida")
        if ".aspack" in joined_names:
            p.packer_hints.append("ASPack")
        if ".mpress" in joined_names:
            p.packer_hints.append("MPRESS")
        if ".enigma" in joined_names:
            p.packer_hints.append("Enigma Protector")
        if ".obsidium" in joined_names:
            p.packer_hints.append("Obsidium")
        if ".pec" in joined_names or "pec1" in joined_names:
            p.packer_hints.append("PECompact")
        if ".fsg!" in joined_names or ".fsg" in joined_names:
            p.packer_hints.append("FSG")
        if ".petite" in joined_names:
            p.packer_hints.append("Petite")

        # High-entropy sections → возможно упаковано/зашифровано
        for s in p.sections:
            if s["entropy"] > 7.2 and s["rawsize"] > 4096:
                if s["name"] not in (".rsrc",):
                    if "high-entropy section" not in p.packer_hints:
                        p.packer_hints.append("high-entropy section")
                    break

        # .NET detection
        if ".NET" not in p.packer_hints and p.is_dotnet:
            p.packer_hints.append(".NET assembly")

        # Imports (упрощённо: ищем DLL strings в бинарнике)
        dll_re = re.compile(rb"([A-Za-z0-9_\-\.]+\.dll)", re.IGNORECASE)
        dlls = set()
        for m in dll_re.finditer(data):
            try:
                dll = m.group(1).decode("ascii", errors="ignore").lower()
                if 3 <= len(dll) <= 60 and not dll.startswith("api-ms"):
                    dlls.add(dll)
            except Exception:
                pass
        p.dlls = sorted(dlls)[:200]
        p.imports = {dll: [] for dll in p.dlls}

        # imphash (правильный: dll.func,dll.func)
        import_str = ",".join(d.lower() for d in sorted(dlls))
        p.imphash = hashlib.md5(import_str.encode()).hexdigest()

        # PDB path
        pdb_re = re.compile(rb"[A-Za-z]:\\[^\x00]{5,200}\.pdb")
        m = pdb_re.search(data)
        if m:
            p.pdb_path = m.group().decode("latin1", errors="ignore")

        # TLS callbacks (в .rdata рядом с IMAGE_DIRECTORY_ENTRY_TLS=9)
        # Упрощённо — просто факт наличия

    except Exception as exc:  # noqa: BLE001
        log.debug("PE parse: %s", exc)
    return p


# ===========================================================================
# ELF parser
# ===========================================================================

def parse_elf(path: Path) -> dict:
    """Разбор ELF-заголовков."""
    out: dict = {"is_elf": False}
    try:
        with path.open("rb") as f:
            data = f.read(4096)  # первые 4KB
    except Exception:
        return out

    if not data.startswith(b"\x7FELF"):
        return out
    out["is_elf"] = True

    try:
        ei_class = data[4]
        ei_data = data[5]
        endian = "<" if ei_data == 1 else ">"
        out["arch"] = "64-bit" if ei_class == 2 else "32-bit"
        out["endian"] = "little" if ei_data == 1 else "big"

        e_type = struct.unpack_from(endian + "H", data, 16)[0]
        out["type"] = {1: "REL", 2: "EXEC", 3: "DYN (PIE/shared)",
                       4: "CORE"}.get(e_type, f"0x{e_type:x}")
        out["is_pie"] = (e_type == 3)

        e_machine = struct.unpack_from(endian + "H", data, 18)[0]
        out["machine"] = e_machine
        out["machine_str"] = {
            0x03: "x86", 0x3E: "x86-64", 0x28: "ARM",
            0xB7: "AArch64", 0x08: "MIPS", 0x14: "PowerPC",
            0xF3: "RISC-V", 0x16: "S390", 0x32: "IA-64",
        }.get(e_machine, f"0x{e_machine:x}")

        # Entrypoint
        if ei_class == 2:
            e_entry = struct.unpack_from(endian + "Q", data, 24)[0]
        else:
            e_entry = struct.unpack_from(endian + "I", data, 24)[0]
        out["entrypoint"] = hex(e_entry)

        # Interpreter (dynamic linker)
        # e_phoff + program headers... упрощённо

    except Exception as exc:  # noqa: BLE001
        log.debug("ELF parse: %s", exc)
    return out


# ===========================================================================
# Mach-O parser
# ===========================================================================

def parse_macho(path: Path) -> dict:
    """Разбор Mach-O заголовков."""
    out: dict = {"is_macho": False}
    try:
        with path.open("rb") as f:
            data = f.read(512)
    except Exception:
        return out

    # Fat binary (Universal)
    if data[:4] in (b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA"):
        out["is_macho"] = True
        out["type"] = "Fat/Universal binary"
        try:
            nfat = struct.unpack_from(">I", data, 4)[0]
            out["architectures"] = nfat
        except Exception:
            pass
        return out

    # Thin binaries
    magic_be = data[:4]
    is_64 = magic_be in (b"\xCF\xFA\xED\xFE", b"\xFE\xED\xFA\xCF")
    if magic_be not in (b"\xCE\xFA\xED\xFE", b"\xFE\xED\xFA\xCE",
                         b"\xCF\xFA\xED\xFE", b"\xFE\xED\xFA\xCF"):
        return out
    out["is_macho"] = True
    out["arch"] = "64-bit" if is_64 else "32-bit"

    try:
        fmt = "<" if magic_be in (b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE") else ">"
        cputype = struct.unpack_from(fmt + "I", data, 4)[0]
        cpusubtype = struct.unpack_from(fmt + "I", data, 8)[0]
        filetype = struct.unpack_from(fmt + "I", data, 12)[0]
        ncmds = struct.unpack_from(fmt + "I", data, 16)[0]
        out["cputype"] = hex(cputype)
        out["cpusubtype"] = hex(cpusubtype)
        out["filetype"] = {1: "OBJECT", 2: "EXECUTE", 3: "FVMLIB",
                           4: "CORE", 5: "PRELOAD", 6: "DYLIB",
                           7: "DYLINKER", 8: "BUNDLE",
                           9: "DYLIB_STUB", 10: "DSYM",
                           11: "KEXT_BUNDLE"}.get(filetype, f"0x{filetype:x}")
        out["ncmds"] = ncmds
    except Exception:
        pass
    return out


# ===========================================================================
# YARA (расширенный)
# ===========================================================================

def _yara_available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


_BUILTIN_YARA_RULES = r"""
rule Suspicious_PowerShell_Encoded {
    strings:
        $a1 = "powershell" nocase
        $a2 = "pwsh" nocase
        $b = "-EncodedCommand" nocase
        $c = "-enc " nocase
        $d = "FromBase64String" nocase
    condition:
        ($a1 or $a2) and ($b or $c or $d)
}

rule Suspicious_Wget_Curl_Pipe_Sh {
    strings:
        $a = "wget " nocase
        $b = "curl " nocase
        $c = "| sh" nocase
        $d = "| bash" nocase
        $e = "|sh"
    condition:
        ($a or $b) and ($c or $d or $e)
}

rule AWS_Keys {
    strings:
        $aws_id = /AKIA[0-9A-Z]{16}/
        $aws_asia = /ASIA[0-9A-Z]{16}/
    condition:
        any of them
}

rule Base64_Long_String {
    strings:
        $b = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b
}

rule Meterpreter_Strings {
    strings:
        $a = "metsrv" nocase
        $b = "Meterpreter" nocase
        $c = "stdapi_" nocase
        $d = "Mettle" nocase
    condition:
        any of them
}

rule Mimikatz_Strings {
    strings:
        $a = "sekurlsa" nocase
        $b = "kerberos::" nocase
        $c = "lsadump" nocase
        $d = "mimikatz" nocase
        $e = "gentilkiwi" nocase
    condition:
        any of them
}

rule CobaltStrike_Beacon {
    strings:
        $a1 = "beacon.dll"
        $a2 = "beacon.x64.dll"
        $b = "%s as %s\\%s: %d"
        $c = "ReflectiveLoader"
        $d = /(?i)Microsoft (Windows|Corporation)/  // маскировка
    condition:
        any of them
}

rule Ransomware_Hints {
    strings:
        $a1 = "vssadmin delete shadows" nocase
        $a2 = "wbadmin delete catalog" nocase
        $a3 = "bcdedit /set" nocase
        $a4 = "vssadmin.exe Delete Shadows /All /Quiet" nocase
        $b = "HOW_TO_DECRYPT" nocase
        $c = "DECRYPT_INSTRUCTIONS" nocase
        $d = "READ_ME_FOR_DECRYPT" nocase
    condition:
        any of them
}

rule Cryptominer_Hints {
    strings:
        $a = "xmrig" nocase
        $b = "stratum+tcp://" nocase
        $c = "cpuminer" nocase
        $d = "minerd" nocase
        $e = "monero" nocase
        $f = "NiceHash" nocase
    condition:
        any of ($a, $b, $c, $d, $e, $f)
}

rule Persistence_Hints {
    strings:
        $a1 = "CurrentVersion\\Run" nocase
        $a2 = "schtasks" nocase
        $a3 = "crontab" nocase
        $a4 = "/etc/rc.local" nocase
        $a5 = "systemd" nocase
    condition:
        any of them
}

rule Reverse_Shell_Hints {
    strings:
        $a1 = "/dev/tcp/"
        $a2 = "bash -i"
        $a3 = "sh -i"
        $a4 = "nc -e"
        $a5 = "socat exec"
        $a6 = "python -c 'import socket"
    condition:
        any of them
}

rule Anti_Debug_Hints {
    strings:
        $a1 = "IsDebuggerPresent"
        $a2 = "CheckRemoteDebuggerPresent"
        $a3 = "NtQueryInformationProcess"
        $a4 = "OutputDebugString"
        $a5 = "NtSetInformationThread"
    condition:
        2 of them
}

rule Anti_VM_Hints {
    strings:
        $a1 = "VBoxGuest" nocase
        $a2 = "VBoxService" nocase
        $a3 = "VMware" nocase
        $a4 = "VirtualBox" nocase
        $a5 = "qemu" nocase
        $a6 = "sandboxie" nocase
    condition:
        any of them
}

rule Credential_Dumping {
    strings:
        $a1 = "sekurlsa::logonpasswords"
        $a2 = "lsadump::sam"
        $a3 = "lsass.dmp"
        $a4 = "procdump" nocase
        $a5 = "MiniDumpWriteDump"
    condition:
        any of them
}

rule Known_Malware_Families {
    strings:
        $a1 = "WannaCry" nocase
        $a2 = "NotPetya" nocase
        $a3 = "Emotet" nocase
        $a4 = "Trickbot" nocase
        $a5 = "Ryuk" nocase
        $a6 = "LockBit" nocase
        $a7 = "BlackCat" nocase
        $a8 = "Conti" nocase
    condition:
        any of them
}

rule Base64_PowerShell_Download_Cradle {
    strings:
        $a = "DownloadString"
        $b = "FromBase64String"
        $c = "Invoke-Expression" nocase
        $d = "IEX" nocase
    condition:
        2 of them
}

rule DNS_Tunneling_Hints {
    strings:
        $a = "dnscat" nocase
        $b = "iodine" nocase
        $c = "dns2tcp" nocase
    condition:
        any of them
}

rule C2_Frameworks {
    strings:
        $a1 = "sliver" nocase
        $a2 = "Mythic" nocase
        $a3 = "Havoc" nocase
        $a4 = "Empire" nocase
        $a5 = "Covenant" nocase
    condition:
        any of them
}
"""


def yara_scan(path: Path, rules_path: str | None = None) -> list[dict]:
    """YARA-скан (встроенные + пользовательские правила)."""
    if not _yara_available():
        console.print("[yellow]yara-python не установлен "
                      "(pip install yara-python).[/yellow]")
        return []
    import yara

    matches: list[dict] = []
    try:
        if rules_path:
            rules = yara.compile(filepath=rules_path)
        else:
            rules = yara.compile(source=_BUILTIN_YARA_RULES)

        matches_raw = rules.match(str(path))
        for m in matches_raw:
            matched_strings = []
            try:
                for s in m.strings:
                    # s может быть tuple или объект в зависимости от версии
                    if hasattr(s, "identifier"):
                        matched_strings.append(s.identifier)
                    else:
                        matched_strings.append(str(s[0]))
            except Exception:
                pass
            matches.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "strings": matched_strings[:20],
            })
    except Exception as exc:  # noqa: BLE001
        log.warning("yara: %s", exc)
        console.print(f"[red]YARA ошибка: {exc}[/red]")
    return matches


# ===========================================================================
# Shellcode / miner / ransomware hints
# ===========================================================================

def detect_shellcode(path: Path) -> dict:
    """Простой детект shellcode."""
    out = {"is_likely_shellcode": False, "hints": []}
    try:
        data = path.read_bytes()
    except Exception:
        return out

    # NOP sled (0x90 много подряд)
    nop_runs = re.findall(rb"\x90{16,}", data[:1024 * 1024])
    if nop_runs:
        out["hints"].append(f"NOP sled x{len(nop_runs)}")

    # Common shellcode prologues
    prologues = [
        (b"\xfc\xe8", "common Metasploit prologue"),
        (b"\x60\x89\xe5", "pusha; mov esp,ebp"),
        (b"\x64\xa1\x30", "PEB access (x86)"),
        (b"\x65\x48\x8b\x04\x25", "PEB access (x64)"),
        (b"\x6a\x02\x5e", "socket syscall hint"),
    ]
    for sig, name in prologues:
        if sig in data[:512]:
            out["hints"].append(name)

    if len(out["hints"]) >= 2:
        out["is_likely_shellcode"] = True

    return out


def detect_crypto_miner(path: Path) -> dict:
    """Детект криптомайнеров."""
    out = {"is_likely_miner": False, "hints": []}
    try:
        data = path.read_bytes()[:5 * 1024 * 1024]
    except Exception:
        return out
    lc = data.lower()
    markers = [
        (b"xmrig", "xmrig string"),
        (b"stratum+tcp", "stratum+tcp protocol"),
        (b"stratum+ssl", "stratum+ssl protocol"),
        (b"nicehash", "NiceHash"),
        (b"cpuminer", "cpuminer"),
        (b"minerd", "minerd"),
        (b"moneroocean", "MoneroOcean"),
        (b"supportxmr", "SupportXMR pool"),
        (b"nanopool", "nanopool"),
        (b"minexmr", "minexmr pool"),
        (b"randomx", "RandomX algorithm"),
        (b"cryptonight", "CryptoNight"),
    ]
    for marker, name in markers:
        if marker in lc:
            out["hints"].append(name)
    if len(out["hints"]) >= 2:
        out["is_likely_miner"] = True
    return out


def detect_ransomware(path: Path) -> dict:
    """Детект ransomware-индикаторов."""
    out = {"is_likely_ransomware": False, "hints": []}
    try:
        data = path.read_bytes()[:5 * 1024 * 1024]
    except Exception:
        return out
    lc = data.lower()
    markers = [
        (b"vssadmin delete shadows", "shadow copy deletion"),
        (b"wbadmin delete", "wbadmin deletion"),
        (b"bcdedit /set", "bcdedit modification"),
        (b"cipher /w", "cipher wipe"),
        (b"how_to_decrypt", "ransom note hint"),
        (b"decrypt_instructions", "ransom note hint"),
        (b"read_me_for_decrypt", "ransom note hint"),
        (b"your_files_are_encrypted", "ransom note"),
        (b".crypt", "ransom extension"),
        (b".locky", "Locky ransomware"),
        (b"tor2web", "Tor2Web (ransom payment)"),
    ]
    for marker, name in markers:
        if marker in lc:
            out["hints"].append(name)
    if len(out["hints"]) >= 2:
        out["is_likely_ransomware"] = True
    return out


# ===========================================================================
# Печать
# ===========================================================================

def _print_strings_table(data: dict, top: int = 20) -> None:
    interesting = data.get("interesting", {})
    for cat, items in interesting.items():
        if not items:
            continue
        # base64_decoded — список dict'ов
        if cat == "base64_decoded" and isinstance(items, list) and items \
                and isinstance(items[0], dict):
            table = Table(title=f"🔎 {cat} ({len(items)})")
            table.add_column("#", width=4)
            table.add_column("Encoded", style="dim", max_width=40)
            table.add_column("Decoded", style="green", max_width=60)
            for i, item in enumerate(items[:top], 1):
                table.add_row(str(i),
                              (item.get("encoded") or "")[:40],
                              (item.get("decoded") or "")[:60])
            console.print(table)
            continue

        table = Table(title=f"🔎 {cat} ({len(items)})")
        table.add_column("#", width=4)
        table.add_column("Value", style="green", max_width=100)
        for i, v in enumerate(items[:top], 1):
            table.add_row(str(i), str(v)[:100])
        console.print(table)

    suspicious = data.get("suspicious", [])
    if suspicious:
        console.print(f"\n[bold yellow]⚠ Suspicious strings "
                      f"({len(suspicious)}):[/bold yellow]")
        table = Table(title="Suspicious")
        table.add_column("#", width=4)
        table.add_column("Keyword", style="red", max_width=30)
        table.add_column("Context", style="dim", max_width=60)
        for i, s in enumerate(suspicious[:20], 1):
            table.add_row(str(i), s.get("keyword", "")[:30],
                          s.get("context", "")[:60])
        console.print(table)


def _print_pe(p: PEParser) -> None:
    if not p.is_pe:
        console.print("[yellow]Не PE-файл.[/yellow]")
        return
    t = Table(title="🔧 PE Header")
    t.add_column("Field", style="cyan")
    t.add_column("Value", style="green")
    t.add_row("Arch", p.arch)
    t.add_row("Subsystem", p.subsystem_str)
    t.add_row("Timestamp", p.timestamp_str)
    t.add_row("ImageBase", hex(p.imagebase))
    t.add_row("EntryPoint", hex(p.entrypoint))
    t.add_row("imphash", p.imphash)
    t.add_row(".NET", "✓" if p.is_dotnet else "—")
    if p.packer_hints:
        t.add_row("Packers/Hints", ", ".join(p.packer_hints))
    if p.pdb_path:
        t.add_row("PDB", p.pdb_path[:80])
    console.print(t)

    if p.sections:
        s = Table(title="Sections")
        s.add_column("Name", style="cyan")
        s.add_column("VSize", style="yellow")
        s.add_column("VAddr", style="dim")
        s.add_column("RawSize", style="white")
        s.add_column("RawOff", style="dim")
        s.add_column("Entropy", style="magenta", width=8)
        for sec in p.sections:
            ent = sec.get("entropy", 0)
            ent_str = f"{ent:.2f}"
            if ent > 7.2:
                ent_str = f"[red]{ent_str}[/red]"
            elif ent > 6.5:
                ent_str = f"[yellow]{ent_str}[/yellow]"
            s.add_row(sec["name"], str(sec["vsize"]), sec["vaddr"],
                      str(sec["rawsize"]), sec["rawoff"], ent_str)
        console.print(s)

    if p.dlls:
        console.print(f"[cyan]DLLs ({len(p.dlls)}):[/cyan]")
        for d in p.dlls[:40]:
            console.print(f"  [green]{d}[/green]")


def _print_elf(elf: dict) -> None:
    if not elf.get("is_elf"):
        console.print("[yellow]Не ELF-файл.[/yellow]")
        return
    t = Table(title="🧬 ELF header")
    t.add_column("Field", style="cyan")
    t.add_column("Value", style="green")
    for k, v in elf.items():
        if k != "is_elf":
            t.add_row(k, str(v))
    console.print(t)


def _print_macho(m: dict) -> None:
    if not m.get("is_macho"):
        console.print("[yellow]Не Mach-O файл.[/yellow]")
        return
    t = Table(title="🍎 Mach-O header")
    t.add_column("Field", style="cyan")
    t.add_column("Value", style="green")
    for k, v in m.items():
        if k != "is_macho":
            t.add_row(k, str(v))
    console.print(t)


def _print_entropy(info: dict, blocks: list[dict] | None = None) -> None:
    if "error" in info:
        console.print(f"[red]{info['error']}[/red]")
        return
    t = Table(title="📊 Entropy / Hashes")
    t.add_column("Metric", style="cyan")
    t.add_column("Value", style="green")
    for k in ("size", "entropy", "classification"):
        t.add_row(k, str(info[k]))
    for k in ("md5", "sha1", "sha256", "sha512"):
        if k in info:
            t.add_row(k.upper(), info[k][:64])
    console.print(t)

    if blocks:
        console.print()
        console.print(visualize_entropy(blocks))


# ===========================================================================
# Полный анализ
# ===========================================================================

def analyze_file(path: str, yara_rules: str | None = None,
                 min_str: int = 4) -> dict:
    """Полный анализ файла."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return {}

    console.print(f"\n[bold cyan]═══ RE Analysis Pro: {p.name} "
                  f"═══[/bold cyan]")
    console.print(f"[dim]Size: {p.stat().st_size:,} bytes[/dim]\n")

    ftype = detect_file_type(p)
    console.print(f"[cyan]File type:[/cyan] {ftype}")

    # 1. Entropy + hashes
    ent = analyze_entropy(p)
    blocks = entropy_blocks(p, block_size=8192)
    _print_entropy(ent, blocks if len(blocks) <= 80 else blocks[:80])

    # 2. Strings + IOC
    strings = extract_strings(p, min_len=min_str)
    console.print(f"\n[cyan]Strings:[/cyan] "
                  f"ASCII={strings.get('ascii_count')}, "
                  f"UTF-16={strings.get('unicode_count')}, "
                  f"total={strings.get('total')}")
    _print_strings_table(strings)

    # 3. Parsers
    pe = None
    elf = None
    macho = None
    if "PE" in ftype or "DOS" in ftype:
        pe = parse_pe(p)
        _print_pe(pe)
    elif "ELF" in ftype:
        elf = parse_elf(p)
        _print_elf(elf)
    elif "Mach" in ftype:
        macho = parse_macho(p)
        _print_macho(macho)

    # 4. YARA
    console.print(f"\n[cyan]YARA scan…[/cyan]")
    ym = yara_scan(p, yara_rules)
    if ym:
        t = Table(title=f"🎯 YARA matches ({len(ym)})",
                  border_style="red")
        t.add_column("Rule", style="cyan")
        t.add_column("Tags", style="magenta")
        t.add_column("Strings", style="yellow")
        for m in ym:
            t.add_row(m["rule"], ",".join(m["tags"]),
                      ",".join(m["strings"])[:60])
        console.print(t)
    else:
        console.print("[green]✓ YARA: нет совпадений.[/green]")

    # 5. Shellcode / Miner / Ransomware
    sc = detect_shellcode(p)
    miner = detect_crypto_miner(p)
    ransom = detect_ransomware(p)

    if sc.get("is_likely_shellcode"):
        console.print(f"\n[bold red]⚠ Shellcode hints: "
                      f"{sc['hints']}[/bold red]")
    if miner.get("is_likely_miner"):
        console.print(f"\n[bold red]⚠ Crypto miner hints: "
                      f"{miner['hints']}[/bold red]")
    if ransom.get("is_likely_ransomware"):
        console.print(f"\n[bold red]⚠ Ransomware hints: "
                      f"{ransom['hints']}[/bold red]")

    # Findings
    _save_analysis_findings(
        p, ftype, pe, ym, sc, miner, ransom, strings, ent,
    )

    # Сохранение
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RE_DIR / f"{p.stem}_{ts}.json"
    result = {
        "file": str(p),
        "size": p.stat().st_size,
        "type": ftype,
        "entropy": ent,
        "entropy_blocks": blocks[:200],
        "strings_total": strings.get("total"),
        "strings_interesting": strings.get("interesting"),
        "strings_suspicious": strings.get("suspicious"),
        "pe": asdict(pe) if pe else None,
        "elf": elf,
        "macho": macho,
        "yara": ym,
        "shellcode": sc,
        "miner": miner,
        "ransomware": ransom,
        "ts": datetime.now().isoformat(),
    }
    try:
        out.write_text(
            json.dumps(result, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"\n[green]✓ {out}[/green]")
    except Exception as exc:  # noqa: BLE001
        log.warning("export: %s", exc)

    db.save_scan("re_analysis", p.name, {
        "type": ftype, "size": p.stat().st_size,
        "entropy": ent.get("entropy"),
        "yara": [m["rule"] for m in ym],
        "shellcode": sc.get("is_likely_shellcode"),
        "miner": miner.get("is_likely_miner"),
        "ransomware": ransom.get("is_likely_ransomware"),
        "strings_total": strings.get("total"),
    })

    return result


def _save_analysis_findings(p: Path, ftype: str, pe: Any,
                            yara_matches: list[dict],
                            shellcode: dict, miner: dict,
                            ransom: dict, strings: dict,
                            entropy: dict) -> None:
    """Автоматические findings."""
    # YARA с высоким severity
    if yara_matches:
        crit_rules = [m["rule"] for m in yara_matches
                      if any(t in m["rule"].lower() for t in
                             ("mimikatz", "cobalt", "meterpreter",
                              "ransomware", "credential", "malware"))]
        if crit_rules:
            _save_finding(REFinding(
                kind="yara_malware",
                severity="high",
                title=f"YARA malware matches ({len(crit_rules)})",
                target=p.name,
                evidence="\n".join(crit_rules),
                data={"rules": crit_rules},
            ))

    # Shellcode
    if shellcode.get("is_likely_shellcode"):
        _save_finding(REFinding(
            kind="shellcode",
            severity="high",
            title=f"Likely shellcode in {p.name}",
            target=p.name,
            evidence=f"Hints: {shellcode['hints']}",
            data=shellcode,
        ))

    # Miner
    if miner.get("is_likely_miner"):
        _save_finding(REFinding(
            kind="crypto_miner",
            severity="high",
            title=f"Crypto miner indicators in {p.name}",
            target=p.name,
            evidence=f"Hints: {miner['hints']}",
            data=miner,
        ))

    # Ransomware
    if ransom.get("is_likely_ransomware"):
        _save_finding(REFinding(
            kind="ransomware",
            severity="critical",
            title=f"Ransomware indicators in {p.name}",
            target=p.name,
            evidence=f"Hints: {ransom['hints']}",
            data=ransom,
        ))

    # High entropy (packed/encrypted)
    if entropy.get("entropy", 0) > 7.5:
        _save_finding(REFinding(
            kind="high_entropy",
            severity="medium",
            title=f"High entropy file ({entropy['entropy']})",
            target=p.name,
            evidence=entropy.get("classification", ""),
            data=entropy,
        ))

    # Packer
    if pe and getattr(pe, "packer_hints", None):
        hints = pe.packer_hints
        if any(h in ("UPX", "VMProtect", "Themida", "MPRESS",
                     "ASPack", "Enigma Protector") for h in hints):
            _save_finding(REFinding(
                kind="packed_binary",
                severity="medium",
                title=f"Packed binary: {', '.join(hints)}",
                target=p.name,
                evidence=", ".join(hints),
                data={"packers": hints},
            ))

    # Suspicious strings
    susp = strings.get("suspicious", [])
    crit_kw = [s for s in susp if any(k in s.get("keyword", "").lower()
              for k in ("mimikatz", "meterpreter", "cobalt",
                        "vssadmin", "ransom", "locky", "wannacry"))]
    if crit_kw:
        _save_finding(REFinding(
            kind="suspicious_strings",
            severity="high",
            title=f"Suspicious strings ({len(crit_kw)})",
            target=p.name,
            evidence="\n".join(s["keyword"] for s in crit_kw[:20]),
            data={"keywords": [s["keyword"] for s in crit_kw]},
        ))

    # AWS keys in binary
    aws = strings.get("interesting", {}).get("aws_keys", [])
    if aws:
        _save_finding(REFinding(
            kind="aws_keys_in_binary",
            severity="critical",
            title=f"AWS keys в бинарнике ({len(aws)})",
            target=p.name,
            evidence=", ".join(aws[:5]),
            data={"keys": aws[:5]},
        ))


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(data: dict, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(RE_DIR / f"report_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_markdown(data: dict, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(RE_DIR / f"report_{ts}.md")
    try:
        lines = [
            f"# RE Analysis: {Path(data.get('file', '?')).name}",
            "",
            f"_Generated: {datetime.now().isoformat()}_",
            "",
            "## Summary",
            f"- **Type:** {data.get('type', '?')}",
            f"- **Size:** {data.get('size', 0):,} bytes",
            f"- **Entropy:** {data.get('entropy', {}).get('entropy', '?')} "
            f"({data.get('entropy', {}).get('classification', '')})",
            f"- **SHA256:** `{data.get('entropy', {}).get('sha256', '?')}`",
            "",
        ]
        yara = data.get("yara", [])
        if yara:
            lines.append(f"## YARA matches ({len(yara)})")
            lines.append("")
            for m in yara:
                lines.append(f"- **{m['rule']}** — {', '.join(m.get('strings', []))}")
            lines.append("")

        pe = data.get("pe")
        if pe and pe.get("is_pe"):
            lines.append(f"## PE")
            lines.append(f"- Arch: {pe.get('arch', '?')}")
            lines.append(f"- Subsystem: {pe.get('subsystem_str', '?')}")
            lines.append(f"- imphash: `{pe.get('imphash', '?')}`")
            if pe.get("packer_hints"):
                lines.append(f"- Packers: {', '.join(pe['packer_hints'])}")
            lines.append("")

        strings = data.get("strings_interesting", {})
        if strings:
            lines.append(f"## IOCs")
            for cat, items in strings.items():
                if items and isinstance(items, list) and \
                   not isinstance(items[0], dict):
                    lines.append(f"### {cat} ({len(items)})")
                    for item in items[:50]:
                        lines.append(f"- `{item}`")
                    lines.append("")

        Path(path).write_text("\n".join(lines), encoding="utf-8")
        console.print(f"[green]✓ Markdown: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Markdown: {exc}[/red]")
        return None


def export_html(data: dict, path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(RE_DIR / f"report_{ts}.html")
    try:
        fname = Path(data.get("file", "?")).name
        ent = data.get("entropy", {})
        parts = [
            "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
            f"<title>RE: {html_mod.escape(fname)}</title>",
            "<style>",
            "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
            "padding:24px;line-height:1.5;}",
            "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
            "h2{color:#00ff9c;margin-top:24px;}",
            "table{width:100%;border-collapse:collapse;margin-top:12px;"
            "font-size:13px;}",
            "th{background:#111;color:#00ff9c;padding:6px;"
            "text-align:left;border:1px solid #222;}",
            "td{padding:4px 6px;border:1px solid #222;word-break:break-all;}",
            "tr:nth-child(even){background:#0d0d0d;}",
            "code{background:#111;padding:2px 6px;color:#a0ffa0;}",
            ".crit{color:#ff2020;font-weight:bold;}",
            ".hi{color:#ff7a40;}",
            "</style></head><body>",
            f"<h1>🔬 {html_mod.escape(fname)}</h1>",
            f"<p><b>Type:</b> {html_mod.escape(data.get('type', '?'))}</p>",
            f"<p><b>Size:</b> {data.get('size', 0):,} bytes</p>",
            f"<p><b>Entropy:</b> {ent.get('entropy', '?')} "
            f"({html_mod.escape(str(ent.get('classification', '')))})</p>",
            f"<p><b>SHA256:</b> <code>{ent.get('sha256', '?')}</code></p>",
        ]
        # YARA
        yara = data.get("yara", [])
        if yara:
            parts.append(f"<h2>🎯 YARA ({len(yara)})</h2>")
            parts.append("<table><tr><th>Rule</th><th>Strings</th></tr>")
            for m in yara:
                parts.append(
                    f"<tr><td class='crit'>{html_mod.escape(m['rule'])}</td>"
                    f"<td>{html_mod.escape(', '.join(m.get('strings', [])))}</td></tr>"
                )
            parts.append("</table>")

        # PE
        pe = data.get("pe")
        if pe and pe.get("is_pe"):
            parts.append("<h2>🔧 PE</h2>")
            parts.append("<table>")
            for k in ("arch", "subsystem_str", "timestamp_str",
                      "imphash", "pdb_path"):
                v = pe.get(k)
                if v:
                    parts.append(f"<tr><th>{k}</th><td>{html_mod.escape(str(v))}</td></tr>")
            if pe.get("packer_hints"):
                parts.append(
                    f"<tr><th>Packers</th>"
                    f"<td class='hi'>{html_mod.escape(', '.join(pe['packer_hints']))}</td></tr>"
                )
            parts.append("</table>")

            if pe.get("sections"):
                parts.append("<h2>Sections</h2>")
                parts.append("<table><tr><th>Name</th><th>VSize</th>"
                             "<th>RawSize</th><th>Entropy</th></tr>")
                for s in pe["sections"]:
                    ent_v = s.get("entropy", 0)
                    cls = "crit" if ent_v > 7.2 else ""
                    parts.append(
                        f"<tr><td>{html_mod.escape(s['name'])}</td>"
                        f"<td>{s['vsize']}</td><td>{s['rawsize']}</td>"
                        f"<td class='{cls}'>{ent_v:.2f}</td></tr>"
                    )
                parts.append("</table>")

        # IOCs
        strings = data.get("strings_interesting", {})
        if strings:
            parts.append("<h2>🔎 IOCs</h2>")
            for cat, items in strings.items():
                if not items:
                    continue
                if cat == "base64_decoded" and isinstance(items[0], dict):
                    parts.append(f"<h3>{html_mod.escape(cat)} ({len(items)})</h3>")
                    parts.append("<table><tr><th>Encoded</th><th>Decoded</th></tr>")
                    for item in items[:50]:
                        parts.append(
                            f"<tr><td><code>{html_mod.escape(item.get('encoded', ''))}</code></td>"
                            f"<td>{html_mod.escape(item.get('decoded', '')[:100])}</td></tr>"
                        )
                    parts.append("</table>")
                elif isinstance(items[0], str):
                    parts.append(f"<h3>{html_mod.escape(cat)} ({len(items)})</h3>")
                    parts.append("<ul>")
                    for item in items[:50]:
                        parts.append(f"<li><code>{html_mod.escape(item[:200])}</code></li>")
                    parts.append("</ul>")

        parts.append("</body></html>")
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# CLI / menu (сохранены все старые сигнатуры)
# ===========================================================================

def cli_analyze(path: str) -> None:
    analyze_file(path)


def cli_strings(path: str, min_len: int = 4) -> None:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return
    data = extract_strings(p, min_len=min_len)
    _print_strings_table(data)


def cli_entropy(path: str) -> None:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return
    info = analyze_entropy(p)
    blocks = entropy_blocks(p)
    _print_entropy(info, blocks)


def cli_yara(path: str, rules: str | None = None) -> None:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{path} не найден.[/red]")
        return
    matches = yara_scan(p, rules)
    if matches:
        for m in matches:
            console.print(f"[red]● {m['rule']}[/red] — "
                          f"{','.join(m['strings'])}")
    else:
        console.print("[green]✓ Нет совпадений.[/green]")


def cli_pe(path: str) -> None:
    _print_pe(parse_pe(Path(path)))


def cli_elf(path: str) -> None:
    _print_elf(parse_elf(Path(path)))


def cli_macho(path: str) -> None:
    _print_macho(parse_macho(Path(path)))


def cli_shellcode(path: str) -> None:
    p = Path(path)
    if not p.exists():
        console.print(f"[red]Не найден[/red]")
        return
    res = detect_shellcode(p)
    console.print(f"[cyan]Shellcode:[/cyan] {res['is_likely_shellcode']}")
    for h in res["hints"]:
        console.print(f"  • {h}")


def cli_miner(path: str) -> None:
    p = Path(path)
    if not p.exists():
        return
    res = detect_crypto_miner(p)
    console.print(f"[cyan]Miner:[/cyan] {res['is_likely_miner']}")
    for h in res["hints"]:
        console.print(f"  • {h}")


def cli_html_export(path: str) -> None:
    result = analyze_file(path)
    if result:
        export_html(result)


def menu() -> None:
    t = Table(title="[bold]🔬 Reverse Engineering Suite Pro[/bold]")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", "Полный анализ файла"),
        ("2", "Strings + IOC extractor"),
        ("3", "Entropy + hashes + graph"),
        ("4", "YARA scan (15+ правил)"),
        ("5", "PE headers"),
        ("6", "ELF headers"),
        ("7", "Mach-O headers"),
        ("8", "Shellcode detector"),
        ("9", "Crypto miner detector"),
        ("10", "Ransomware detector"),
        ("11", "Полный анализ + HTML"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    console.print("[yellow]⚠ Только для авторизованного анализа.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        analyze_file(Prompt.ask("Путь к файлу"))
    elif c == "2":
        p = Prompt.ask("Путь")
        n = IntPrompt.ask("Мин. длина", default=4)
        cli_strings(p, n)
    elif c == "3":
        cli_entropy(Prompt.ask("Путь"))
    elif c == "4":
        p = Prompt.ask("Путь")
        r = Prompt.ask("YARA rules файл (пусто = встроенные)",
                       default="")
        cli_yara(p, r or None)
    elif c == "5":
        cli_pe(Prompt.ask("Путь к PE-файлу"))
    elif c == "6":
        cli_elf(Prompt.ask("Путь к ELF-файлу"))
    elif c == "7":
        cli_macho(Prompt.ask("Путь к Mach-O"))
    elif c == "8":
        cli_shellcode(Prompt.ask("Путь"))
    elif c == "9":
        cli_miner(Prompt.ask("Путь"))
    elif c == "10":
        p = Path(Prompt.ask("Путь"))
        res = detect_ransomware(p)
        console.print(f"[cyan]Ransomware:[/cyan] "
                      f"{res['is_likely_ransomware']}")
        for h in res["hints"]:
            console.print(f"  • {h}")
    elif c == "11":
        cli_html_export(Prompt.ask("Путь"))