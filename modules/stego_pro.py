"""
Steganography Pro: скрытие текста и произвольных файлов в PNG и WAV.

Возможности:
  - AES-256-GCM шифрование payload (пароль → ключ через PBKDF2-SHA256, 200k итераций)
  - Встраивание в младшие биты (LSB) пикселей PNG или сэмплов WAV
  - Извлечение с проверкой целостности (GCM-тег ловит неверный пароль/повреждение)
  - Chi-square анализ (Westfeld-Pfitzmann) для обнаружения скрытых данных

Зависимости: Pillow, cryptography (уже в requirements.txt).
Формат пакета:
    [MAGIC 'CSTX' 4B][version 1B][enc_len 8B big-endian][enc_len байт шифртекста]
    enc = salt(16) + nonce(12) + AES-GCM(ciphertext+tag)
"""
import array
import os
import wave
from pathlib import Path

from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

MAGIC = b"CSTX"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
HEADER_LEN = len(MAGIC) + 1 + 8          # 13 байт
PBKDF2_ITER = 200_000
GCM_TAG_LEN = 16


# ===========================================================================
# Крипто
# ===========================================================================

def _derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-SHA256 → 32-байтовый ключ."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return kdf.derive(password.encode("utf-8"))


def _encrypt_payload(payload: bytes, password: str) -> bytes:
    """salt(16) + nonce(12) + ciphertext+tag."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, payload, None)
    return salt + nonce + ct


def _decrypt_payload(blob: bytes, password: str) -> bytes:
    """Расшифровать salt+nonce+ct. Бросит исключение при неверном пароле."""
    if len(blob) < SALT_LEN + NONCE_LEN + GCM_TAG_LEN:
        raise ValueError("Шифртекст слишком короткий")
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = blob[SALT_LEN + NONCE_LEN:]
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)


def _build_packet(payload: bytes, password: str) -> bytes:
    """Сформировать полный пакет для встраивания."""
    enc = _encrypt_payload(payload, password)
    header = MAGIC + bytes([VERSION]) + len(enc).to_bytes(8, "big")
    return header + enc


# ===========================================================================
# Утилиты битов
# ===========================================================================

def _bytes_to_bits(data: bytes) -> str:
    """Байты → строка '0101...'."""
    return "".join(f"{b:08b}" for b in data)


def _bits_to_bytes(bits: str) -> bytes:
    """Строка бит (кратна 8) → байты."""
    n = len(bits) // 8
    return bytes(int(bits[i * 8:(i + 1) * 8], 2) for i in range(n))


def _parse_packet_from_bits(bits: str, password: str) -> bytes:
    """Разобрать пакет из строки бит."""
    pos = 0

    def read_bytes(n: int) -> bytes:
        nonlocal pos
        need = n * 8
        if pos + need > len(bits):
            raise ValueError("Недостаточно бит для чтения")
        out = bytearray()
        for _ in range(n):
            out.append(int(bits[pos:pos + 8], 2))
            pos += 8
        return bytes(out)

    magic = read_bytes(4)
    if magic != MAGIC:
        raise ValueError(
            "Magic-байты не совпадают — скрытых данных не найдено "
            "или файл не наш"
        )
    ver = read_bytes(1)[0]
    if ver != VERSION:
        raise ValueError(f"Версия {ver} не поддерживается")
    enc_len = int.from_bytes(read_bytes(8), "big")
    enc = read_bytes(enc_len)
    return _decrypt_payload(enc, password)


# ===========================================================================
# PNG: встраивание/извлечение
# ===========================================================================

def _embed_png(src_path: Path, out_path: Path, packet: bytes) -> None:
    img = Image.open(src_path).convert("RGB")
    w, h = img.size
    pixels = list(img.getdata())
    bits = _bytes_to_bits(packet)
    capacity_bits = len(pixels) * 3
    if len(bits) > capacity_bits:
        raise ValueError(
            f"Не хватает места в PNG: нужно {len(bits)} бит, "
            f"есть {capacity_bits} ({w}×{h}×3)"
        )

    new_pixels = []
    bi = 0
    for (r, g, b) in pixels:
        if bi < len(bits):
            r = (r & 0xFE) | int(bits[bi]); bi += 1
        if bi < len(bits):
            g = (g & 0xFE) | int(bits[bi]); bi += 1
        if bi < len(bits):
            b = (b & 0xFE) | int(bits[bi]); bi += 1
        new_pixels.append((r, g, b))

    out = Image.new("RGB", (w, h))
    out.putdata(new_pixels)
    out.save(out_path, "PNG")


def _extract_png(path: Path, max_bytes: int = 64 * 1024 * 1024) -> str:
    """Извлечь поток бит из PNG (не более max_bytes байт)."""
    img = Image.open(path).convert("RGB")
    limit_bits = max_bytes * 8
    bits = []
    for (r, g, b) in img.getdata():
        bits.append(str(r & 1))
        bits.append(str(g & 1))
        bits.append(str(b & 1))
        if len(bits) >= limit_bits:
            break
    return "".join(bits)


# ===========================================================================
# WAV: встраивание/извлечение (16-бит PCM)
# ===========================================================================

def _read_wav_samples(path: Path):
    with wave.open(str(path), "rb") as w:
        params = w.getparams()
        frames = w.readframes(w.getnframes())
    if params.sampwidth != 2:
        raise ValueError(
            f"Поддерживается только 16-бит PCM WAV, у тебя {params.sampwidth * 8}-бит"
        )
    samples = array.array("h")
    samples.frombytes(frames)
    return params, samples


def _write_wav_samples(path: Path, params, samples: array.array) -> None:
    with wave.open(str(path), "wb") as w:
        w.setparams(params)
        w.writeframes(samples.tobytes())


def _embed_wav(src_path: Path, out_path: Path, packet: bytes) -> None:
    params, samples = _read_wav_samples(src_path)
    bits = _bytes_to_bits(packet)
    if len(bits) > len(samples):
        raise ValueError(
            f"Не хватает места в WAV: нужно {len(bits)} бит, "
            f"есть {len(samples)} сэмплов"
        )
    for i, bit in enumerate(bits):
        samples[i] = (samples[i] & ~1) | int(bit)
    _write_wav_samples(out_path, params, samples)


def _extract_wav(path: Path, max_bytes: int = 64 * 1024 * 1024) -> str:
    _, samples = _read_wav_samples(path)
    limit_bits = max_bytes * 8
    bits = []
    for s in samples:
        bits.append(str(s & 1))
        if len(bits) >= limit_bits:
            break
    return "".join(bits)


# ===========================================================================
# Chi-square (Westfeld–Pfitzmann) — детектор скрытых данных
# ===========================================================================

def _chi_square_values(values: list[int]) -> dict:
    """Chi-square по парам (2i, 2i+1) для списка значений 0..255."""
    counts = [0] * 256
    for v in values:
        counts[v & 0xFF] += 1

    chi = 0.0
    for i in range(128):
        even = counts[2 * i]
        odd = counts[2 * i + 1]
        expected = (even + odd) / 2.0
        if expected > 0:
            chi += ((even - expected) ** 2) / expected
            chi += ((odd - expected) ** 2) / expected

    # df=127: критическое значение p=0.95 → ~100.9 (ниже = слишком равномерно)
    likely = chi < 100.9
    return {
        "chi_square": round(chi, 2),
        "dof": 127,
        "likely_hidden": likely,
        "interpretation": (
            "Похоже на скрытые данные (LSB слишком равномерно распределены)"
            if likely
            else "Похоже, скрытых данных нет (естественное распределение)"
        ),
    }


def chi_square_png(path: Path) -> dict:
    """Chi-square анализ PNG."""
    img = Image.open(path).convert("RGB")
    values: list[int] = []
    for r, g, b in img.getdata():
        values.append(r)
        values.append(g)
        values.append(b)
    return _chi_square_values(values)


def chi_square_wav(path: Path) -> dict:
    """Chi-square анализ WAV (младшие 8 бит каждого сэмпла)."""
    _, samples = _read_wav_samples(path)
    values = [(s & 0xFF) for s in samples]
    return _chi_square_values(values)


# ===========================================================================
# Высокоуровневое API
# ===========================================================================

def hide_in_png(src: str, out: str, payload: bytes, password: str) -> None:
    src_p, out_p = Path(src), Path(out)
    if not src_p.exists():
        raise FileNotFoundError(f"Не найден: {src}")
    packet = _build_packet(payload, password)
    _embed_png(src_p, out_p, packet)
    size_kb = out_p.stat().st_size / 1024
    console.print(
        f"[green]✓ Спрятано {len(payload)} байт payload "
        f"({len(packet)} байт пакета) в {out_p} ({size_kb:.1f} KB)[/green]"
    )
    db.save_scan("stego_png_hide", str(src_p),
                 {"out": str(out_p), "payload_len": len(payload)})


def extract_from_png(path: str, password: str) -> bytes:
    bits = _extract_png(Path(path))
    payload = _parse_packet_from_bits(bits, password)
    return payload


def hide_in_wav(src: str, out: str, payload: bytes, password: str) -> None:
    src_p, out_p = Path(src), Path(out)
    if not src_p.exists():
        raise FileNotFoundError(f"Не найден: {src}")
    packet = _build_packet(payload, password)
    _embed_wav(src_p, out_p, packet)
    size_kb = out_p.stat().st_size / 1024
    console.print(
        f"[green]✓ Спрятано {len(payload)} байт payload "
        f"({len(packet)} байт пакета) в {out_p} ({size_kb:.1f} KB)[/green]"
    )
    db.save_scan("stego_wav_hide", str(src_p),
                 {"out": str(out_p), "payload_len": len(payload)})


def extract_from_wav(path: str, password: str) -> bytes:
    bits = _extract_wav(Path(path))
    return _parse_packet_from_bits(bits, password)


# ===========================================================================
# Меню (интерактив)
# ===========================================================================

def _ask_password(confirm: bool = False) -> str:
    pwd = Prompt.ask("Пароль", password=True)
    if confirm:
        pwd2 = Prompt.ask("Повтори пароль", password=True)
        if pwd != pwd2:
            console.print("[red]Пароли не совпадают.[/red]")
            raise ValueError("password mismatch")
    return pwd


def _do_hide_text_png() -> None:
    src = Prompt.ask("Исходный PNG")
    out = Prompt.ask("Куда сохранить PNG", default="stego_out.png")
    text = Prompt.ask("Текст для сокрытия")
    pwd = _ask_password(confirm=True)
    try:
        hide_in_png(src, out, text.encode("utf-8"), pwd)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def _do_extract_text_png() -> None:
    src = Prompt.ask("PNG с данными")
    pwd = _ask_password()
    try:
        payload = extract_from_png(src, pwd)
        try:
            console.print(f"[green]{payload.decode('utf-8')}[/green]")
        except UnicodeDecodeError:
            console.print(f"[yellow]Данные не текст, hex:[/yellow] {payload.hex()}")
        db.save_scan("stego_png_extract", src, {"len": len(payload)})
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def _do_hide_file_png() -> None:
    src = Prompt.ask("Исходный PNG")
    out = Prompt.ask("Куда сохранить PNG", default="stego_out.png")
    file_path = Prompt.ask("Путь к файлу для сокрытия")
    if not Path(file_path).exists():
        console.print("[red]Файл не найден.[/red]")
        return
    data = Path(file_path).read_bytes()
    pwd = _ask_password(confirm=True)
    try:
        hide_in_png(src, out, data, pwd)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def _do_extract_file_png() -> None:
    src = Prompt.ask("PNG с данными")
    out = Prompt.ask("Куда сохранить извлечённый файл", default="extracted.bin")
    pwd = _ask_password()
    try:
        payload = extract_from_png(src, pwd)
        Path(out).write_bytes(payload)
        console.print(f"[green]✓ Извлечено {len(payload)} байт → {out}[/green]")
        db.save_scan("stego_png_extract_file", src,
                     {"out": out, "len": len(payload)})
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def _do_hide_file_wav() -> None:
    src = Prompt.ask("Исходный WAV (16-бит PCM)")
    out = Prompt.ask("Куда сохранить WAV", default="stego_out.wav")
    file_path = Prompt.ask("Путь к файлу для сокрытия")
    if not Path(file_path).exists():
        console.print("[red]Файл не найден.[/red]")
        return
    data = Path(file_path).read_bytes()
    pwd = _ask_password(confirm=True)
    try:
        hide_in_wav(src, out, data, pwd)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def _do_extract_file_wav() -> None:
    src = Prompt.ask("WAV с данными")
    out = Prompt.ask("Куда сохранить извлечённый файл", default="extracted.bin")
    pwd = _ask_password()
    try:
        payload = extract_from_wav(src, pwd)
        Path(out).write_bytes(payload)
        console.print(f"[green]✓ Извлечено {len(payload)} байт → {out}[/green]")
        db.save_scan("stego_wav_extract_file", src,
                     {"out": out, "len": len(payload)})
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")


def _do_chi_square_png() -> None:
    src = Prompt.ask("PNG для анализа")
    try:
        info = chi_square_png(Path(src))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    table = Table(title=f"Chi-square (PNG) — {src}")
    table.add_column("Показатель", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("χ²", str(info["chi_square"]))
    table.add_row("df", str(info["dof"]))
    table.add_row("Порог p=0.95", "100.9")
    table.add_row("Похоже на скрытые данные",
                  "[red]да[/red]" if info["likely_hidden"] else "[green]нет[/green]")
    table.add_row("Вывод", info["interpretation"])
    console.print(table)
    db.save_scan("stego_chi_png", src, info)


def _do_chi_square_wav() -> None:
    src = Prompt.ask("WAV для анализа")
    try:
        info = chi_square_wav(Path(src))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    table = Table(title=f"Chi-square (WAV) — {src}")
    table.add_column("Показатель", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("χ²", str(info["chi_square"]))
    table.add_row("df", str(info["dof"]))
    table.add_row("Порог p=0.95", "100.9")
    table.add_row("Похоже на скрытые данные",
                  "[red]да[/red]" if info["likely_hidden"] else "[green]нет[/green]")
    table.add_row("Вывод", info["interpretation"])
    console.print(table)
    db.save_scan("stego_chi_wav", src, info)


def menu() -> None:
    """Меню Steganography Pro."""
    table = Table(title="[bold]Steganography Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Спрятать текст в PNG (AES-256-GCM)"),
        ("2", "Извлечь текст из PNG"),
        ("3", "Спрятать файл в PNG"),
        ("4", "Извлечь файл из PNG"),
        ("5", "Спрятать файл в WAV (16-бит PCM)"),
        ("6", "Извлечь файл из WAV"),
        ("7", "Chi-square анализ PNG (детект скрытых данных)"),
        ("8", "Chi-square анализ WAV"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])
    {
        "1": _do_hide_text_png,
        "2": _do_extract_text_png,
        "3": _do_hide_file_png,
        "4": _do_extract_file_png,
        "5": _do_hide_file_wav,
        "6": _do_extract_file_wav,
        "7": _do_chi_square_png,
        "8": _do_chi_square_wav,
    }[c]()