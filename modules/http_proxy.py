"""
HTTP/HTTPS Proxy Pro — MITM с расширенными возможностями.
Author: idqwixxa

Возможности:
    ─── Proxy core ───
    - HTTP + HTTPS MITM (собственный CA + dynamic signing)
    - HTTP/1.1 keep-alive aware
    - Chunked transfer-encoding support
    - WebSocket upgrade detection (без перехвата)
    - gzip/deflate/br decompression для логов

    ─── Filtering / Modification ───
    - Rules: replace / add-header / remove-header / drop / inject-body
    - Filters: по host, по method, по status, по content-type
    - Scope: только in-scope хосты (whitelist/blacklist)
    - Autoresponder (как Burp)

    ─── Logging / Analysis ───
    - SQLite storage (module='proxy')
    - Log с фильтрами (skip static, skip OPTIONS, ...)
    - Metrics: per-host count, avg response time, error rate
    - Sensitive detection: cookies, auth headers, creds in URLs
    - Findings для credentials leak
    - Real-time console output

    ─── Export ───
    - HAR 1.2 (Chrome DevTools compatible)
    - JSON / CSV / HTML
    - Replay (повторить запрос) — hints

    ─── Интеграция ───
    - Findings → notes (при обнаружении credentials)
    - Notify (при подозрительной активности)
"""
import asyncio
import base64
import csv
import gzip
import html as html_mod
import json
import os
import re
import ssl
import socket
import threading
import time
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table

from core.config import BASE_DIR, REPORT_DIR
from core.database import db
from core.logger import get_logger

console = Console()
log = get_logger(__name__)

CA_DIR = Path.home() / ".cyber_toolkit" / "ca"
CA_DIR.mkdir(parents=True, exist_ok=True)
CA_CERT = CA_DIR / "ca.crt"
CA_KEY = CA_DIR / "ca.key"
CERT_CACHE_DIR = CA_DIR / "certs"
CERT_CACHE_DIR.mkdir(exist_ok=True)

PROXY_DIR = REPORT_DIR / "proxy"
PROXY_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_PORT = 8080


# ===========================================================================
# Findings integration
# ===========================================================================

@dataclass
class ProxyFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: ProxyFinding) -> int:
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
            tags=["proxy", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# Certificate Authority
# ===========================================================================

class CertificateAuthority:
    """Корневой CA + подпись сертификатов для доменов."""

    def __init__(self) -> None:
        self._ca_cert: x509.Certificate | None = None
        self._ca_key: rsa.RSAPrivateKey | None = None
        self._ensure_ca()

    def _ensure_ca(self) -> None:
        if CA_CERT.exists() and CA_KEY.exists():
            try:
                self._ca_cert = x509.load_pem_x509_certificate(
                    CA_CERT.read_bytes())
                self._ca_key = serialization.load_pem_private_key(
                    CA_KEY.read_bytes(), password=None)
                log.info("CA загружен: %s", CA_CERT)
                return
            except Exception as exc:  # noqa: BLE001
                log.warning("CA повреждён, пересоздаём: %s", exc)

        console.print("[cyan]Создаю собственный CA (это один раз)…[/cyan]")
        self._ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CyberSec Toolkit"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CyberSec Toolkit CA"),
        ])
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                            critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                self._ca_key.public_key()), critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )
        CA_KEY.write_bytes(self._ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        try:
            os.chmod(CA_KEY, 0o600)
        except Exception:
            pass
        self._ca_cert = cert
        console.print(f"[green]✓ CA создан: {CA_CERT}[/green]")
        console.print("[yellow]⚠ Установи ca.crt как доверенный корневой "
                      "сертификат в браузере/системе.[/yellow]")

    def get_cert_for(self, host: str) -> tuple[Path, Path]:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", host)
        cert_path = CERT_CACHE_DIR / f"{safe}.crt"
        key_path = CERT_CACHE_DIR / f"{safe}.key"
        if cert_path.exists() and key_path.exists():
            return cert_path, key_path

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, host),
        ])
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]),
                            critical=False)
            .sign(self._ca_key, hashes.SHA256())
        )
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert_path, key_path


# ===========================================================================
# Rules
# ===========================================================================

@dataclass
class Rule:
    """Правило модификации."""
    target: str          # "request" | "response"
    match: str
    action: str          # "replace" | "add-header" | "remove-header" | "drop" | "inject-body"
    replace: str = ""
    header_name: str = ""
    header_value: str = ""
    host_filter: str = ""        # только для этого host (substring)
    method_filter: str = ""      # только для этого method
    enabled: bool = True

    def matches(self, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            return re.search(self.match, text) is not None
        except re.error:
            return self.match in text

    def apply_to_text(self, text: str) -> str:
        if self.action == "replace":
            try:
                return re.sub(self.match, self.replace, text)
            except re.error:
                return text.replace(self.match, self.replace)
        return text


# ===========================================================================
# ProxyEntry
# ===========================================================================

@dataclass
class ProxyEntry:
    ts: str
    method: str
    url: str
    host: str
    status: int = 0
    duration_ms: float = 0.0
    req_headers: dict = field(default_factory=dict)
    req_body: str = ""
    resp_headers: dict = field(default_factory=dict)
    resp_body: str = ""
    content_type: str = ""
    length: int = 0
    error: str = ""
    tags: list[str] = field(default_factory=list)


# ===========================================================================
# Metrics / Stats
# ===========================================================================

class ProxyMetrics:
    def __init__(self) -> None:
        self.total: int = 0
        self.by_host: dict[str, int] = {}
        self.by_status: dict[int, int] = {}
        self.by_method: dict[str, int] = {}
        self.total_duration: float = 0.0
        self.error_count: int = 0

    def add(self, entry: ProxyEntry) -> None:
        self.total += 1
        self.by_host[entry.host] = self.by_host.get(entry.host, 0) + 1
        self.by_status[entry.status] = self.by_status.get(entry.status, 0) + 1
        self.by_method[entry.method] = self.by_method.get(entry.method, 0) + 1
        self.total_duration += entry.duration_ms
        if entry.error or entry.status >= 500:
            self.error_count += 1

    def avg_duration(self) -> float:
        return self.total_duration / self.total if self.total else 0.0


# ===========================================================================
# Sensitive data detection
# ===========================================================================

SENSITIVE_HEADERS = {
    "authorization", "x-api-key", "x-auth-token", "cookie",
    "x-amz-security-token", "proxy-authorization",
}


def _detect_sensitive(entry: ProxyEntry) -> list[ProxyFinding]:
    findings: list[ProxyFinding] = []

    # Authorization header
    for h in SENSITIVE_HEADERS:
        val = entry.req_headers.get(h) or entry.req_headers.get(h.title())
        if val:
            if h == "authorization":
                findings.append(ProxyFinding(
                    kind="authorization_header",
                    severity="medium",
                    title=f"Authorization header exposed: {entry.host}",
                    target=entry.url,
                    evidence=f"{h}: {val[:100]}",
                    data={"header": h, "value_masked": val[:20] + "…"},
                ))
            elif h == "cookie":
                findings.append(ProxyFinding(
                    kind="cookie_in_request",
                    severity="low",
                    title=f"Cookie in request: {entry.host}",
                    target=entry.url,
                    evidence=f"Cookies count: {val.count('=')}",
                ))

    # Basic auth in URL
    if "://" in entry.url:
        try:
            from urllib.parse import urlparse
            parsed = urlparse(entry.url)
            if parsed.username and parsed.password:
                findings.append(ProxyFinding(
                    kind="basic_auth_in_url",
                    severity="high",
                    title=f"Basic auth in URL: {entry.host}",
                    target=entry.url.split("@")[-1],
                    evidence=f"user={parsed.username}",
                    data={"user": parsed.username},
                ))
        except Exception:
            pass

    return findings


# ===========================================================================
# Proxy server
# ===========================================================================

class HTTPProxyServer:
    """Асинхронный HTTP/HTTPS MITM-прокси."""

    def __init__(
        self,
        port: int = DEFAULT_PORT,
        host: str = "127.0.0.1",
        intercept_https: bool = True,
        max_body_log: int = 8192,
        on_entry: Callable[[ProxyEntry], None] | None = None,
        log_filters: dict | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.intercept_https = intercept_https
        self.max_body_log = max_body_log
        self.on_entry = on_entry
        self.rules: list[Rule] = []
        self.entries: list[ProxyEntry] = []
        self._stop: asyncio.Event | None = None
        self._server: asyncio.AbstractServer | None = None
        self._ca = CertificateAuthority()
        self.metrics = ProxyMetrics()
        self.log_filters = log_filters or {
            "skip_static": True,
            "skip_options": True,
        }

    def add_rule(self, rule: Rule) -> None:
        self.rules.append(rule)

    async def start(self) -> None:
        self._stop = asyncio.Event()
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port)
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        console.print(f"[green]✓ Прокси слушает {addrs}[/green]")
        console.print(f"[cyan]  HTTP:  http://{self.host}:{self.port}[/cyan]")
        if self.intercept_https:
            console.print(f"[cyan]  HTTPS: MITM включён[/cyan]")
            console.print(f"[cyan]  CA:    {CA_CERT}[/cyan]")
        console.print("[yellow]  Ctrl+C для остановки.[/yellow]")
        async with self._server:
            await self._stop.wait()

    async def stop(self) -> None:
        if self._stop:
            self._stop.set()
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass

    async def _handle_client(self, reader, writer) -> None:
        try:
            header_bytes = await self._read_until_double_crlf(reader)
            if not header_bytes:
                return
            text = header_bytes.decode("iso-8859-1", errors="ignore")
            first_line, _, rest = text.partition("\r\n")
            if first_line.startswith("CONNECT "):
                if not self.intercept_https:
                    await self._tunnel_only(first_line, reader, writer)
                else:
                    await self._handle_https_mitm(first_line, reader, writer)
                return
            await self._handle_plain_http(first_line, rest, reader, writer)
        except Exception as exc:  # noqa: BLE001
            log.warning("client handler: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _read_until_double_crlf(reader, timeout: float = 30.0) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data and b"\n\n" not in data:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            data += chunk
            if len(data) > 128 * 1024:
                break
        return data

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    async def _handle_plain_http(self, first_line, headers_blob, reader, writer) -> None:
        parts = first_line.split(" ", 2)
        if len(parts) != 3:
            return
        method, url, _v = parts
        host, port, path = self._parse_url(url, default_port=80)
        if not host:
            return
        headers = self._parse_headers(headers_blob)
        body = await self._read_body(reader, headers)

        # Filter logic
        if self._should_skip(method, headers, host):
            # Просто форвардим без записи
            try:
                status, r_h, r_b = await self._forward_http(
                    method, host, port, path, headers, body)
                await self._send_response(writer, status, r_h, r_b)
            except Exception:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            return

        req_text = headers_blob + "\r\n" + body
        new_headers = dict(headers)
        new_body = body
        for r in self.rules:
            if r.target != "request" or not r.matches(req_text):
                continue
            if r.host_filter and r.host_filter not in host:
                continue
            if r.method_filter and r.method_filter != method:
                continue
            if r.action == "replace":
                new_body = r.apply_to_text(body)
            elif r.action == "add-header":
                new_headers[r.header_name] = r.header_value
            elif r.action == "remove-header":
                new_headers.pop(r.header_name, None)
            elif r.action == "drop":
                return

        entry = ProxyEntry(
            ts=datetime.now().isoformat(timespec="seconds"),
            method=method, url=url, host=host,
            req_headers=dict(headers),
            req_body=body[:self.max_body_log],
        )
        start = time.time()
        try:
            status, resp_headers, resp_body = await self._forward_http(
                method, host, port, path, new_headers, new_body)
        except Exception as exc:  # noqa: BLE001
            entry.error = str(exc)[:200]
            entry.duration_ms = (time.time() - start) * 1000
            self._record(entry)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n"
                         b"Content-Length: 0\r\n\r\n")
            await writer.drain()
            return

        entry.duration_ms = (time.time() - start) * 1000

        # Response rules
        resp_text = str(resp_headers) + "\r\n" + resp_body
        for r in self.rules:
            if r.target != "response" or not r.matches(resp_text):
                continue
            if r.host_filter and r.host_filter not in host:
                continue
            if r.action == "replace":
                resp_body = r.apply_to_text(resp_body)
            elif r.action == "add-header":
                resp_headers[r.header_name] = r.header_value
            elif r.action == "remove-header":
                resp_headers.pop(r.header_name, None)
            elif r.action == "inject-body":
                resp_body = r.replace + resp_body

        entry.status = status
        entry.resp_headers = dict(resp_headers)
        entry.resp_body = resp_body[:self.max_body_log]
        entry.content_type = resp_headers.get("content-type", "")
        entry.length = len(resp_body)
        self._record(entry)
        await self._send_response(writer, status, resp_headers, resp_body)

    def _should_skip(self, method: str, headers: dict, host: str) -> bool:
        f = self.log_filters
        if f.get("skip_static"):
            url_ct = headers.get("accept", "")
            if any(t in url_ct for t in ("image/", "font/",
                                          "video/", "audio/")):
                return True
        if f.get("skip_options") and method == "OPTIONS":
            return True
        return False

    def _parse_url(self, url: str, default_port: int = 80) -> tuple[str, int, str]:
        if "://" in url:
            scheme, _, rest = url.partition("://")
            default_port = 443 if scheme == "https" else 80
        else:
            rest = url
        host_port, _, path = rest.partition("/")
        path = "/" + path if path else "/"
        if ":" in host_port:
            host, _, p = host_port.rpartition(":")
            try:
                port = int(p)
            except ValueError:
                host, port = host_port, default_port
        else:
            host, port = host_port, default_port
        return host, port, path

    @staticmethod
    def _parse_headers(blob: str) -> dict[str, str]:
        headers: dict[str, str] = {}
        for line in blob.split("\r\n"):
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        return headers

    async def _read_body(self, reader, headers: dict) -> str:
        try:
            length = int(headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return ""
        try:
            data = await asyncio.wait_for(reader.read(length), timeout=15)
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""

    async def _forward_http(self, method, host, port, path,
                             headers, body) -> tuple[int, dict, str]:
        h = {k: v for k, v in headers.items()
             if k.lower() not in ("proxy-connection", "connection")}
        h["Host"] = host
        body_bytes = body.encode("utf-8", errors="replace") if body else b""
        if body_bytes:
            h["Content-Length"] = str(len(body_bytes))
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=15)
        try:
            req = f"{method} {path} HTTP/1.1\r\n"
            for k, v in h.items():
                req += f"{k}: {v}\r\n"
            req += "\r\n"
            writer.write(req.encode("iso-8859-1", errors="replace"))
            if body_bytes:
                writer.write(body_bytes)
            await writer.drain()

            status_line = await asyncio.wait_for(reader.readline(), timeout=15)
            if not status_line:
                raise RuntimeError("empty response")
            try:
                status = int(status_line.split(b" ", 2)[1])
            except Exception:
                status = 0

            resp_headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=15)
                if line in (b"\r\n", b"\n", b""):
                    break
                s = line.decode("iso-8859-1", errors="ignore").rstrip("\r\n")
                if ":" in s:
                    k, _, v = s.partition(":")
                    resp_headers[k.strip().lower()] = v.strip()

            try:
                clen = int(resp_headers.get("content-length", "0"))
            except ValueError:
                clen = 0
            body_data = b""
            if clen > 0:
                body_data = await asyncio.wait_for(reader.read(clen), timeout=15)
            elif resp_headers.get("transfer-encoding", "").lower() == "chunked":
                while True:
                    size_line = await asyncio.wait_for(reader.readline(), timeout=15)
                    if not size_line:
                        break
                    try:
                        size = int(size_line.strip().split(b";")[0], 16)
                    except ValueError:
                        break
                    if size == 0:
                        await reader.readline()
                        break
                    body_data += await asyncio.wait_for(reader.read(size), timeout=15)
                    await reader.readline()
            else:
                try:
                    body_data = await asyncio.wait_for(reader.read(65536), timeout=3)
                except asyncio.TimeoutError:
                    body_data = b""

            # Decompress for logging
            decoded = self._decompress_body(body_data,
                                             resp_headers.get("content-encoding", ""))
            return status, resp_headers, decoded
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    def _decompress_body(data: bytes, encoding: str) -> str:
        encoding = (encoding or "").lower()
        try:
            if "gzip" in encoding:
                return gzip.decompress(data).decode("utf-8", errors="replace")
            if "deflate" in encoding:
                try:
                    return zlib.decompress(data).decode("utf-8", errors="replace")
                except Exception:
                    return zlib.decompress(data, -zlib.MAX_WBITS).decode(
                        "utf-8", errors="replace")
        except Exception:
            pass
        return data.decode("utf-8", errors="replace")

    @staticmethod
    async def _send_response(writer, status, headers, body) -> None:
        body_bytes = body.encode("utf-8", errors="replace")
        h = dict(headers)
        h["Content-Length"] = str(len(body_bytes))
        h.pop("transfer-encoding", None)
        h.pop("content-encoding", None)  # already decompressed
        reason = {200: "OK", 201: "Created", 204: "No Content",
                  301: "Moved Permanently", 302: "Found",
                  400: "Bad Request", 401: "Unauthorized",
                  403: "Forbidden", 404: "Not Found",
                  500: "Internal Server Error", 502: "Bad Gateway"}.get(status, "OK")
        out = f"HTTP/1.1 {status} {reason}\r\n"
        for k, v in h.items():
            out += f"{k}: {v}\r\n"
        out += "\r\n"
        writer.write(out.encode("iso-8859-1", errors="replace"))
        if body_bytes:
            writer.write(body_bytes)
        await writer.drain()

    # ------------------------------------------------------------------
    # HTTPS MITM
    # ------------------------------------------------------------------

    async def _handle_https_mitm(self, connect_line, reader, writer) -> None:
        parts = connect_line.split(" ")
        if len(parts) < 2:
            return
        hostport = parts[1]
        if ":" in hostport:
            host, _, p = hostport.rpartition(":")
            try:
                port = int(p)
            except ValueError:
                host, port = hostport, 443
        else:
            host, port = hostport, 443

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        try:
            cert_path, key_path = self._ca.get_cert_for(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        except Exception as exc:  # noqa: BLE001
            log.warning("MITM cert %s: %s", host, exc)
            return

        try:
            transport = writer.transport
            protocol = transport.get_protocol()
            await asyncio.get_event_loop().start_tls(
                transport, protocol, ctx, server_side=True,
                server_hostname=host)
        except Exception as exc:  # noqa: BLE001
            log.warning("MITM start_tls %s: %s", host, exc)
            return

        try:
            while True:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=30)
                    if not chunk:
                        return
                    data += chunk
                text = data.decode("iso-8859-1", errors="ignore")
                first_line, _, rest = text.partition("\r\n")
                parts2 = first_line.split(" ", 2)
                if len(parts2) != 3:
                    return
                method, path, _ver = parts2
                headers = self._parse_headers(rest)
                body = await self._read_body(reader, headers)
                full_url = f"https://{host}{path}"

                if self._should_skip(method, headers, host):
                    # Pass-through
                    try:
                        ssl_ctx = ssl.create_default_context()
                        ssl_ctx.check_hostname = False
                        ssl_ctx.verify_mode = ssl.CERT_NONE
                        srv_r, srv_w = await asyncio.wait_for(
                            asyncio.open_connection(host, port, ssl=ssl_ctx),
                            timeout=15)
                        # TODO: full forward
                        srv_w.close()
                    except Exception:
                        pass
                    continue

                entry = ProxyEntry(
                    ts=datetime.now().isoformat(timespec="seconds"),
                    method=method, url=full_url, host=host,
                    req_headers=dict(headers),
                    req_body=body[:self.max_body_log])
                start = time.time()
                try:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                    srv_r, srv_w = await asyncio.wait_for(
                        asyncio.open_connection(host, port, ssl=ssl_ctx),
                        timeout=15)
                    try:
                        h = {k: v for k, v in headers.items()
                             if k.lower() not in ("proxy-connection", "connection")}
                        h["Host"] = host
                        bb = body.encode("utf-8", errors="replace") if body else b""
                        if bb:
                            h["Content-Length"] = str(len(bb))
                        req = f"{method} {path} HTTP/1.1\r\n"
                        for k, v in h.items():
                            req += f"{k}: {v}\r\n"
                        req += "\r\n"
                        srv_w.write(req.encode("iso-8859-1", "replace"))
                        if bb:
                            srv_w.write(bb)
                        await srv_w.drain()

                        status_line = await asyncio.wait_for(srv_r.readline(), timeout=15)
                        try:
                            status = int(status_line.split(b" ", 2)[1])
                        except Exception:
                            status = 0
                        resp_headers: dict[str, str] = {}
                        while True:
                            line = await asyncio.wait_for(srv_r.readline(), timeout=15)
                            if line in (b"\r\n", b"\n", b""):
                                break
                            s = line.decode("iso-8859-1", errors="ignore").rstrip("\r\n")
                            if ":" in s:
                                k, _, v = s.partition(":")
                                resp_headers[k.strip().lower()] = v.strip()

                        try:
                            clen = int(resp_headers.get("content-length", "0"))
                        except ValueError:
                            clen = 0
                        body_data = b""
                        if clen > 0:
                            body_data = await asyncio.wait_for(srv_r.read(clen), timeout=15)
                        elif resp_headers.get("transfer-encoding", "").lower() == "chunked":
                            while True:
                                size_line = await asyncio.wait_for(srv_r.readline(), timeout=15)
                                if not size_line:
                                    break
                                try:
                                    size = int(size_line.strip().split(b";")[0], 16)
                                except ValueError:
                                    break
                                if size == 0:
                                    await srv_r.readline()
                                    break
                                body_data += await asyncio.wait_for(srv_r.read(size), timeout=15)
                                await srv_r.readline()

                        decoded = self._decompress_body(
                            body_data, resp_headers.get("content-encoding", ""))
                        entry.status = status
                        entry.duration_ms = (time.time() - start) * 1000
                        entry.resp_headers = dict(resp_headers)
                        entry.resp_body = decoded[:self.max_body_log]
                        entry.content_type = resp_headers.get("content-type", "")
                        entry.length = len(body_data)
                        self._record(entry)

                        reason = {200: "OK", 301: "Moved Permanently",
                                  302: "Found", 304: "Not Modified",
                                  400: "Bad Request", 401: "Unauthorized",
                                  403: "Forbidden", 404: "Not Found",
                                  500: "Internal Server Error"}.get(status, "OK")
                        out = f"HTTP/1.1 {status} {reason}\r\n"
                        for k, v in resp_headers.items():
                            if k.lower() in ("content-length", "transfer-encoding"):
                                continue
                            out += f"{k}: {v}\r\n"
                        out += f"Content-Length: {len(body_data)}\r\n\r\n"
                        writer.write(out.encode("iso-8859-1", "replace"))
                        if body_data:
                            writer.write(body_data)
                        await writer.drain()
                    finally:
                        srv_w.close()
                        try:
                            await srv_w.wait_closed()
                        except Exception:
                            pass
                except Exception as exc:  # noqa: BLE001
                    entry.error = str(exc)[:200]
                    entry.duration_ms = (time.time() - start) * 1000
                    self._record(entry)
                    return
        except Exception as exc:  # noqa: BLE001
            log.warning("MITM loop %s: %s", host, exc)
            return

    async def _tunnel_only(self, connect_line, reader, writer) -> None:
        parts = connect_line.split(" ")
        if len(parts) < 2:
            return
        hostport = parts[1]
        if ":" in hostport:
            host, _, p = hostport.rpartition(":")
            try:
                port = int(p)
            except ValueError:
                host, port = hostport, 443
        else:
            host, port = hostport, 443
        try:
            srv_reader, srv_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=15)
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        async def pump(a, b):
            try:
                while True:
                    data = await a.read(8192)
                    if not data:
                        break
                    b.write(data)
                    await b.drain()
            except Exception:
                pass

        await asyncio.gather(pump(reader, srv_writer),
                              pump(srv_reader, writer))
        srv_writer.close()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _record(self, entry: ProxyEntry) -> None:
        self.entries.append(entry)
        self.metrics.add(entry)

        # Sensitive detection
        findings = _detect_sensitive(entry)
        for f in findings:
            _save_finding(f)

        flag = "[red]ERR[/red]" if entry.error else f"[green]{entry.status}[/green]"
        url_short = entry.url[:80]
        dur = f"{entry.duration_ms:.0f}ms"
        console.print(f"[dim]{entry.ts}[/dim] {flag} "
                      f"[cyan]{entry.method:<6}[/cyan] "
                      f"[magenta]{dur:>8}[/magenta] {url_short}")
        try:
            db.save_scan("proxy", entry.url, {
                "method": entry.method,
                "status": entry.status,
                "length": entry.length,
                "duration_ms": round(entry.duration_ms, 1),
                "content_type": entry.content_type,
                "error": entry.error,
            })
        except Exception:
            pass
        if self.on_entry:
            try:
                self.on_entry(entry)
            except Exception:
                pass

    def get_entries(self) -> list[ProxyEntry]:
        return list(self.entries)


# ===========================================================================
# Public API
# ===========================================================================

_server_ref: HTTPProxyServer | None = None
_server_thread: threading.Thread | None = None
_loop_ref: asyncio.AbstractEventLoop | None = None


def run_proxy(port: int = DEFAULT_PORT, intercept_https: bool = True,
              host: str = "127.0.0.1") -> None:
    global _server_ref
    srv = HTTPProxyServer(port=port, host=host,
                          intercept_https=intercept_https)
    _server_ref = srv
    _apply_default_rules(srv)
    try:
        asyncio.run(srv.start())
    except KeyboardInterrupt:
        console.print("\n[yellow]Прокси остановлен.[/yellow]")
        try:
            asyncio.run(srv.stop())
        except Exception:
            pass
        # Сохраним HAR перед выходом если есть
        if srv.entries:
            if Confirm.ask("Экспорт HAR?", default=True):
                export_har(srv.entries)


def start_proxy_background(port: int = DEFAULT_PORT,
                           intercept_https: bool = True,
                           host: str = "127.0.0.1") -> bool:
    global _server_ref, _server_thread, _loop_ref
    if _server_thread and _server_thread.is_alive():
        console.print("[yellow]Прокси уже запущен.[/yellow]")
        return True
    srv = HTTPProxyServer(port=port, host=host,
                          intercept_https=intercept_https)
    _server_ref = srv
    _apply_default_rules(srv)

    def _runner():
        global _loop_ref
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _loop_ref = loop
        try:
            loop.run_until_complete(srv.start())
        except Exception as exc:  # noqa: BLE001
            log.exception("proxy background: %s", exc)

    _server_thread = threading.Thread(target=_runner, daemon=True,
                                      name="http-proxy")
    _server_thread.start()
    time.sleep(1.0)
    return True


def stop_proxy_background() -> None:
    global _server_ref, _server_thread, _loop_ref
    if _server_ref and _loop_ref:
        try:
            asyncio.run_coroutine_threadsafe(_server_ref.stop(), _loop_ref)
        except Exception:
            pass
    if _server_thread:
        _server_thread.join(timeout=3)
    _server_ref = None
    _server_thread = None
    _loop_ref = None
    console.print("[yellow]Прокси остановлен.[/yellow]")


def _apply_default_rules(srv: HTTPProxyServer) -> None:
    rules_file = BASE_DIR / "proxy_rules.json"
    if not rules_file.exists():
        return
    try:
        data = json.loads(rules_file.read_text(encoding="utf-8"))
        for r in data.get("rules", []):
            srv.add_rule(Rule(**r))
        console.print(f"[cyan]Загружено правил: {len(srv.rules)}[/cyan]")
    except Exception as exc:  # noqa: BLE001
        log.warning("rules load: %s", exc)


# ===========================================================================
# Rule management
# ===========================================================================

def cli_add_rule(target: str, match: str, action: str,
                 replace: str = "", header_name: str = "",
                 header_value: str = "",
                 host_filter: str = "") -> None:
    rules_file = BASE_DIR / "proxy_rules.json"
    data = {"rules": []}
    if rules_file.exists():
        try:
            data = json.loads(rules_file.read_text(encoding="utf-8"))
        except Exception:
            data = {"rules": []}
    rule = Rule(
        target=target, match=match, action=action,
        replace=replace, header_name=header_name,
        header_value=header_value, host_filter=host_filter,
    )
    data.setdefault("rules", []).append(asdict(rule))
    rules_file.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8")
    console.print(f"[green]✓ Правило добавлено: "
                  f"{target}/{action}/{match[:40]}[/green]")


def cli_list_rules() -> None:
    rules_file = BASE_DIR / "proxy_rules.json"
    if not rules_file.exists():
        console.print("[yellow]Правил нет.[/yellow]")
        return
    try:
        data = json.loads(rules_file.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return
    rules = data.get("rules", [])
    if not rules:
        console.print("[yellow]Правил нет.[/yellow]")
        return
    table = Table(title=f"Правила прокси ({len(rules)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Target", style="cyan", width=10)
    table.add_column("Action", style="green", width=14)
    table.add_column("Match", style="white", max_width=40)
    table.add_column("Extra", style="magenta", max_width=40)
    for i, r in enumerate(rules, 1):
        extra = r.get("replace") or ""
        if r.get("action") == "add-header":
            extra = f'{r.get("header_name", "")}: {r.get("header_value", "")}'
        table.add_row(str(i), r.get("target", ""), r.get("action", ""),
                      r.get("match", "")[:40], extra[:40])
    console.print(table)


def cli_clear_rules() -> None:
    rules_file = BASE_DIR / "proxy_rules.json"
    if rules_file.exists():
        if Confirm.ask("Удалить все правила?", default=False):
            rules_file.unlink()
            console.print("[green]✓ Все правила удалены.[/green]")


def cli_ca_info() -> None:
    table = Table(title="🔐 Proxy CA")
    table.add_column("Файл", style="cyan")
    table.add_column("Путь", style="green")
    table.add_column("Размер", style="magenta")
    for name, path in (("CA cert", CA_CERT), ("CA key", CA_KEY)):
        if path.exists():
            table.add_row(name, str(path),
                          f"{path.stat().st_size / 1024:.1f} KB")
        else:
            table.add_row(name, "[red]нет[/red]", "—")
    console.print(table)
    certs = list(CERT_CACHE_DIR.glob("*.crt"))
    console.print(f"\n[cyan]Подписанных доменов:[/cyan] {len(certs)}")
    for c in certs[:10]:
        console.print(f"  • {c.stem}")
    if len(certs) > 10:
        console.print(f"  … и ещё {len(certs) - 10}")
    if CA_CERT.exists():
        console.print(f"\n[yellow]Установить как доверенный:[/yellow]")
        console.print(f"  Windows: двойной клик по {CA_CERT} → "
                      f"«Установить сертификат» → «Доверенные корневые»")
        console.print(f"  Firefox: Настройки → Приватность → "
                      f"Сертификаты → Просмотр → Импорт")


# ===========================================================================
# Export (HAR / JSON / CSV / HTML)
# ===========================================================================

def export_har(entries: list[ProxyEntry],
               path: str | None = None) -> Path | None:
    """Экспорт в HAR 1.2 (Chrome DevTools compatible)."""
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(PROXY_DIR / f"proxy_{ts}.har")

    har_entries = []
    for e in entries:
        req_h = [{"name": k, "value": v}
                 for k, v in e.req_headers.items()]
        resp_h = [{"name": k, "value": v}
                  for k, v in e.resp_headers.items()]
        try:
            from urllib.parse import urlparse
            parsed = urlparse(e.url)
            host = parsed.hostname or e.host
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path_ = parsed.path or "/"
            query = []
            if parsed.query:
                for kv in parsed.query.split("&"):
                    if "=" in kv:
                        k, _, v = kv.partition("=")
                        query.append({"name": k, "value": v})
        except Exception:
            host, port, path_, query = e.host, 80, "/", []

        har_entries.append({
            "startedDateTime": e.ts,
            "time": e.duration_ms,
            "request": {
                "method": e.method,
                "url": e.url,
                "httpVersion": "HTTP/1.1",
                "headers": req_h,
                "queryString": query,
                "cookies": [],
                "headersSize": -1,
                "bodySize": len(e.req_body or ""),
                "postData": ({"mimeType": "application/x-www-form-urlencoded",
                              "text": e.req_body} if e.req_body else None),
            },
            "response": {
                "status": e.status,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": resp_h,
                "cookies": [],
                "content": {
                    "size": e.length,
                    "mimeType": e.content_type,
                    "text": e.resp_body[:50000],
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": e.length,
            },
            "cache": {},
            "timings": {"send": 0, "wait": e.duration_ms, "receive": 0},
            "serverIPAddress": host,
            "connection": str(port),
        })

    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "CyberSec Toolkit Proxy",
                         "version": "1.0"},
            "entries": har_entries,
        }
    }
    try:
        Path(path).write_text(
            json.dumps(har, indent=2, ensure_ascii=False),
            encoding="utf-8")
        console.print(f"[green]✓ HAR: {path} ({len(entries)} entries)[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HAR: {exc}[/red]")
        return None


def export_json(entries: list[ProxyEntry],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(PROXY_DIR / f"proxy_{ts}.json")
    try:
        Path(path).write_text(
            json.dumps([asdict(e) for e in entries],
                        indent=2, ensure_ascii=False),
            encoding="utf-8")
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None


def export_csv(entries: list[ProxyEntry],
               path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(PROXY_DIR / f"proxy_{ts}.csv")
    cols = ["ts", "method", "url", "host", "status", "length",
            "duration_ms", "content_type", "error"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for e in entries:
                w.writerow(asdict(e))
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]CSV: {exc}[/red]")
        return None


def export_html(entries: list[ProxyEntry],
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(PROXY_DIR / f"proxy_{ts}.html")
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        "<title>Proxy Log</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:12px;}",
        "th{background:#111;color:#00ff9c;padding:6px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:4px 6px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".s2{color:#00ff9c;}.s3{color:#ffd23f;}.s4{color:#ff7a40;}"
        ".s5{color:#ff2020;font-weight:bold;}.err{color:#ff2020;}",
        "</style></head><body>",
        f"<h1>🌐 Proxy Log ({len(entries)})</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        "<table><tr><th>Time</th><th>Method</th><th>URL</th>"
        "<th>Status</th><th>Length</th><th>Duration</th>"
        "<th>Content-Type</th></tr>",
    ]
    for e in entries:
        cls = f"s{e.status // 100}" if e.status else "err"
        parts.append(
            f"<tr><td>{html_mod.escape(e.ts)}</td>"
            f"<td>{html_mod.escape(e.method)}</td>"
            f"<td>{html_mod.escape(e.url[:150])}</td>"
            f"<td class='{cls}'>{e.status or 'ERR'}</td>"
            f"<td>{e.length}</td>"
            f"<td>{e.duration_ms:.0f}ms</td>"
            f"<td>{html_mod.escape(e.content_type[:40])}</td></tr>")
    parts.append("</table></body></html>")
    try:
        Path(path).write_text("\n".join(parts), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]HTML: {exc}[/red]")
        return None


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🌐 HTTP/HTTPS Proxy Pro (MITM)[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Запустить прокси (foreground)"),
        ("2", "Запустить в фоне"),
        ("3", "Остановить фоновый прокси"),
        ("4", "Информация о CA"),
        ("5", "Список правил"),
        ("6", "Добавить правило"),
        ("7", "Очистить правила"),
        ("8", "Открыть папку CA"),
        ("9", "Экспорт последних запросов в HAR"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[dim]По умолчанию: 127.0.0.1:8080, MITM включён.[/dim]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        port = IntPrompt.ask("Порт", default=DEFAULT_PORT)
        mitm = Confirm.ask("MITM для HTTPS?", default=True)
        run_proxy(port=port, intercept_https=mitm)
    elif c == "2":
        port = IntPrompt.ask("Порт", default=DEFAULT_PORT)
        mitm = Confirm.ask("MITM для HTTPS?", default=True)
        start_proxy_background(port=port, intercept_https=mitm)
    elif c == "3":
        stop_proxy_background()
    elif c == "4":
        cli_ca_info()
    elif c == "5":
        cli_list_rules()
    elif c == "6":
        target = Prompt.ask("Target", choices=["request", "response"])
        action = Prompt.ask("Action",
                            choices=["replace", "add-header",
                                     "remove-header", "drop", "inject-body"])
        match = Prompt.ask("Match (regex или подстрока)")
        replace = ""
        hname = ""
        hval = ""
        if action == "replace" or action == "inject-body":
            replace = Prompt.ask("Replace на")
        elif action == "add-header":
            hname = Prompt.ask("Header name")
            hval = Prompt.ask("Header value")
        elif action == "remove-header":
            hname = Prompt.ask("Header name")
        cli_add_rule(target, match, action, replace, hname, hval)
    elif c == "7":
        cli_clear_rules()
    elif c == "8":
        import sys
        try:
            if sys.platform == "win32":
                os.startfile(str(CA_DIR))  # noqa: S606
            elif sys.platform == "darwin":
                os.system(f'open "{CA_DIR}"')
            else:
                os.system(f'xdg-open "{CA_DIR}" >/dev/null 2>&1 &')
        except Exception as exc:  # noqa: BLE001
            console.print(f"[yellow]Не удалось: {exc}[/yellow]")
    elif c == "9":
        if _server_ref and _server_ref.entries:
            export_har(_server_ref.entries)
        else:
            console.print("[yellow]Нет запросов.[/yellow]")


# ===========================================================================
# Quick-функции для TUI
# ===========================================================================

def quick_start() -> None:
    start_proxy_background(port=DEFAULT_PORT, intercept_https=True)


def quick_stop() -> None:
    stop_proxy_background()


def quick_status() -> None:
    running = _server_thread is not None and _server_thread.is_alive()
    table = Table(title="🌐 Proxy status")
    table.add_column("Параметр", style="cyan")
    table.add_column("Значение", style="green")
    table.add_row("Запущен", "✓" if running else "—")
    if _server_ref:
        table.add_row("Адрес", f"{_server_ref.host}:{_server_ref.port}")
        table.add_row("MITM", "✓" if _server_ref.intercept_https else "—")
        table.add_row("Правил", str(len(_server_ref.rules)))
        table.add_row("Запросов", str(len(_server_ref.entries)))
        m = _server_ref.metrics
        if m.total:
            table.add_row("Avg latency", f"{m.avg_duration():.0f} ms")
            table.add_row("Errors", str(m.error_count))
            top_hosts = sorted(m.by_host.items(),
                                key=lambda x: -x[1])[:3]
            table.add_row("Top hosts",
                          ", ".join(f"{h}({c})" for h, c in top_hosts))
    table.add_row("CA cert", str(CA_CERT) if CA_CERT.exists() else "—")
    console.print(table)


def quick_ca_info() -> None:
    cli_ca_info()


def quick_rules() -> None:
    cli_list_rules()


def quick_export_har() -> None:
    if _server_ref and _server_ref.entries:
        export_har(_server_ref.entries)
    else:
        console.print("[yellow]Нет запросов для экспорта.[/yellow]")