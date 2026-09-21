"""
API Fuzzing Suite — расширенный набор для тестирования REST/GraphQL API.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── Импорт спецификаций ───
    - OpenAPI / Swagger 2.0 + 3.0/3.1 (с $ref resolution, allOf/oneOf/anyOf)
    - Postman Collection v2
    - HAR (HTTP Archive)
    - Auto-discovery: /openapi.json, /swagger.json, /api-docs

    ─── Аудит endpoints ───
    - Массовый fuzz всех endpoints из spec (GET/POST/PUT/PATCH/DELETE)
    - Auth-bypass matrix (без токена / с пустым / с мусорным)
    - HTTP-method confusion (HEAD/PUT/OPTIONS/PATCH/TRACE)
    - Content-Type confusion (json→xml→form→yaml)
    - Mass assignment (добавление в body скрытых полей: role, admin, is_admin)
    - SSRF-параметры (url/callback/webhook/redirect → collaborator)
    - ReDoS (regex catastrophic backtracking payloads)
    - Idempotency (повтор POST → детект race/fee-дубликата)
    - JWT-атаки (alg:none, weak secret, algorithm confusion)
    - BOLA / IDOR (matrix по ID/GUID/slug + браузер полей ответа)
    - Rate-limit test (адаптивный, с burst detection и throttling-анализом)
    - GraphQL (introspection, suggestions, batching, alias, deep)

    ─── Отчётность ───
    - Rich-таблица в реальном времени
    - JSON / CSV / HTML (тёмная тема) / Markdown
    - Автосохранение findings в notes (kind="finding")
    - Уведомление через notifier по завершении
"""
import csv
import html as html_mod
import json
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import requests
import yaml
from rich.console import Console
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn,
)

from core.config import config, REPORT_DIR
from core.database import db
from core.logger import get_logger
from utils.helpers import confirm_external, normalize_url

console = Console()
log = get_logger(__name__)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_DIR = REPORT_DIR / "api_fuzz"
API_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 15
DEFAULT_THREADS = 12
MAX_BODY_LOG = 800


# ===========================================================================
# Модели
# ===========================================================================

@dataclass
class Endpoint:
    method: str
    path: str
    summary: str = ""
    operation_id: str = ""
    params: list[dict] = field(default_factory=list)
    body_schema: dict | None = None
    auth_required: bool = False
    tags: list[str] = field(default_factory=list)
    deprecated: bool = False


@dataclass
class EndpointResult:
    method: str
    url: str
    status: int = 0
    length: int = 0
    content_type: str = ""
    response_snippet: str = ""
    headers: dict = field(default_factory=dict)
    error: str = ""
    duration_ms: float = 0.0


@dataclass
class Finding:
    """Единица находки, сохраняется в notes."""
    kind: str          # auth_bypass | bola | mass_assignment | method_confusion |
                       # content_type | ssrf | redos | idempotency | jwt | ratelimit
                       # graphql_introspection | graphql_batch | method_put_allowed | ...
    severity: str      # critical | high | medium | low | info
    title: str
    url: str = ""
    method: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


# ===========================================================================
# OpenAPI / Swagger / Postman / HAR — загрузка спецификаций
# ===========================================================================

def _resolve_refs(obj: Any, spec: dict, seen: set | None = None) -> Any:
    """Разворачивает $ref в OpenAPI-спецификации."""
    seen = seen or set()
    if isinstance(obj, dict):
        if "$ref" in obj:
            ref = obj["$ref"]
            if ref in seen:
                return {}   # защита от циклов
            seen.add(ref)
            # Только локальные ссылки
            if ref.startswith("#/"):
                parts = ref[2:].split("/")
                target: Any = spec
                for part in parts:
                    part = part.replace("~1", "/").replace("~0", "~")
                    if isinstance(target, dict):
                        target = target.get(part, {})
                    else:
                        return {}
                return _resolve_refs(target, spec, seen)
            return obj
        return {k: _resolve_refs(v, spec, seen) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_refs(x, spec, seen) for x in obj]
    return obj


def load_openapi(path_or_url: str) -> dict | None:
    """Загрузить OpenAPI/Swagger spec (file или URL)."""
    data: Any = None
    if path_or_url.startswith(("http://", "https://")):
        try:
            r = requests.get(
                path_or_url, timeout=TIMEOUT, verify=False,
                headers={"User-Agent": config.USER_AGENT},
            )
            r.raise_for_status()
            try:
                data = r.json()
            except Exception:
                data = yaml.safe_load(r.text)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка загрузки spec: {exc}[/red]")
            return None
    else:
        p = Path(path_or_url)
        if not p.exists():
            console.print(f"[red]Файл {p} не найден.[/red]")
            return None
        try:
            text = p.read_text(encoding="utf-8")
            try:
                data = json.loads(text)
            except Exception:
                data = yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Ошибка чтения {p}: {exc}[/red]")
            return None

    if not data:
        console.print("[red]Пустой spec.[/red]")
        return None

    # Разворачиваем $ref
    try:
        data = _resolve_refs(data, data)
    except Exception as exc:  # noqa: BLE001
        log.warning("$ref resolution: %s", exc)

    version = data.get("openapi") or data.get("swagger", "")
    console.print(f"[green]✓ OpenAPI/Swagger {version}[/green]")
    return data


def load_postman(path: str) -> dict | None:
    """Загрузить Postman Collection v2 и сконвертировать в pseudo-spec."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{p} не найден.[/red]")
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None

    paths: dict = {}
    def _walk(items: list) -> None:
        for it in items or []:
            if "item" in it:
                _walk(it["item"])
                continue
            req = it.get("request")
            if not req:
                continue
            method = (req.get("method") or "GET").lower()
            url = req.get("url")
            if isinstance(url, dict):
                raw = url.get("raw", "")
                path = raw
                if "://" in path:
                    path = "/" + path.split("://", 1)[1].split("/", 1)[-1]
                if "?" in path:
                    path = path.split("?")[0]
            else:
                path = str(url)
            if not path.startswith("/"):
                path = "/" + path
            paths.setdefault(path, {})[method] = {
                "summary": it.get("name", ""),
                "tags": ["postman"],
            }
    _walk(data.get("item", []))
    console.print(f"[green]✓ Postman: {len(paths)} paths[/green]")
    return {"paths": paths, "openapi": "postman"}


def load_har(path: str) -> dict | None:
    """Загрузить HAR и сконвертировать в pseudo-spec."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red]{p} не найден.[/red]")
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]JSON: {exc}[/red]")
        return None

    entries = (data.get("log") or {}).get("entries") or []
    paths: dict = {}
    for e in entries:
        req = e.get("request") or {}
        method = (req.get("method") or "GET").lower()
        url = req.get("url", "")
        try:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path or "/"
        except Exception:
            path = "/"
        paths.setdefault(path, {})[method] = {
            "summary": url[:80],
            "tags": ["har"],
        }
    console.print(f"[green]✓ HAR: {len(paths)} paths[/green]")
    return {"paths": paths, "openapi": "har"}


def parse_endpoints(spec: dict) -> list[Endpoint]:
    """Извлечь список endpoints из spec."""
    endpoints: list[Endpoint] = []
    paths = spec.get("paths", {}) or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in ("get", "post", "put", "delete",
                                       "patch", "head", "options", "trace"):
                continue
            if not isinstance(op, dict):
                op = {}
            ep = Endpoint(
                method=method.upper(),
                path=path,
                summary=(op.get("summary") or op.get("description") or "")[:120],
                operation_id=op.get("operationId", ""),
                tags=op.get("tags", []) or [],
                auth_required=bool(op.get("security")) or bool(
                    spec.get("security")),
                deprecated=bool(op.get("deprecated")),
            )
            # Параметры (levels: op + path)
            params = (op.get("parameters") or []) + \
                     (methods.get("parameters") or [])
            for p in params:
                if not isinstance(p, dict):
                    continue
                sch = p.get("schema") or {}
                ep.params.append({
                    "name": p.get("name", ""),
                    "in": p.get("in", ""),
                    "type": sch.get("type", "string"),
                    "format": sch.get("format", ""),
                    "example": p.get("example") or sch.get("example"),
                    "required": bool(p.get("required")),
                })
            # RequestBody
            rb = op.get("requestBody")
            if rb and isinstance(rb, dict):
                content = rb.get("content", {}) or {}
                for ctype, cdata in content.items():
                    ep.body_schema = {
                        "content_type": ctype,
                        "schema": cdata.get("schema") if isinstance(cdata, dict)
                                  else None,
                        "example": cdata.get("example") if isinstance(cdata, dict)
                                   else None,
                    }
                    break
            # Swagger 2: consumes/produces
            if not ep.body_schema and method.lower() in ("post", "put", "patch"):
                consumes = op.get("consumes") or spec.get("consumes") or \
                           ["application/json"]
                if op.get("parameters"):
                    body_param = next(
                        (p for p in op["parameters"]
                         if isinstance(p, dict) and p.get("in") == "body"),
                        None,
                    )
                    if body_param:
                        ep.body_schema = {
                            "content_type": consumes[0],
                            "schema": body_param.get("schema"),
                            "example": None,
                        }
            endpoints.append(ep)
    return endpoints


def get_base_url(spec: dict) -> str:
    """Определить базовый URL из spec."""
    servers = spec.get("servers", []) or []
    if servers and isinstance(servers[0], dict):
        url = servers[0].get("url", "")
        return url.rstrip("/") if url else ""
    host = spec.get("host", "")
    base_path = spec.get("basePath", "")
    schemes = spec.get("schemes") or ["https"]
    if host:
        return f"{schemes[0]}://{host}{base_path}".rstrip("/")
    return ""


def discover_openapi(base_url: str) -> dict | None:
    """Auto-discovery OpenAPI по типовым путям."""
    base = normalize_url(base_url).rstrip("/")
    candidates = [
        "/openapi.json", "/openapi.yaml",
        "/swagger.json", "/swagger.yaml",
        "/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/api/swagger.json", "/api/openapi.json",
        "/spec", "/docs/openapi.json",
    ]
    console.print(f"[cyan]🔍 Auto-discovery OpenAPI на {base}[/cyan]")
    for path in candidates:
        url = base + path
        try:
            r = requests.get(url, timeout=8, verify=False,
                             headers={"User-Agent": config.USER_AGENT})
            if r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                try:
                    data = yaml.safe_load(r.text)
                except Exception:
                    continue
            if data and ("paths" in data or "openapi" in data
                          or "swagger" in data):
                console.print(f"[green]✓ Найден: {url}[/green]")
                return data
        except Exception:
            continue
    console.print("[yellow]Spec не найден в типовых местах.[/yellow]")
    return None


# ===========================================================================
# Генерация тел и параметров
# ===========================================================================

def _example_from_schema(schema: dict | None, depth: int = 0) -> Any:
    """Сгенерировать пример из JSON Schema (с ограничением рекурсии)."""
    if depth > 6 or not isinstance(schema, dict):
        return "test"
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    # allOf / oneOf / anyOf
    for key in ("allOf", "oneOf", "anyOf"):
        if key in schema and schema[key]:
            return _example_from_schema(schema[key][0], depth + 1)
    t = schema.get("type", "string")
    if t == "integer":
        return 1
    if t == "number":
        return 1.5
    if t == "boolean":
        return True
    if t == "array":
        items = schema.get("items") or {}
        return [_example_from_schema(items, depth + 1)]
    if t == "object":
        props = schema.get("properties") or {}
        return {k: _example_from_schema(v, depth + 1)
                for k, v in props.items()}
    if t == "string":
        fmt = schema.get("format", "")
        return {
            "email": "test@example.com",
            "date": "2024-01-01",
            "date-time": "2024-01-01T00:00:00Z",
            "uuid": "00000000-0000-0000-0000-000000000001",
            "uri": "https://example.com/",
            "password": "P@ssw0rd!",
            "binary": "test",
            "byte": "dGVzdA==",
        }.get(fmt, "test")
    return "test"


def build_request_url(base: str, ep: Endpoint,
                      path_params: dict | None = None) -> str:
    """Подставить path-параметры в URL."""
    path = ep.path
    pp = path_params or {}
    for m in re.finditer(r"\{([^}]+)\}", path):
        name = m.group(1)
        value = str(pp.get(name, 1))
        path = path.replace(f"{{{name}}}", urllib.parse.quote(value, safe=""))
    return urllib.parse.urljoin(base + "/", path.lstrip("/"))


def build_query_params(ep: Endpoint) -> dict:
    """Собрать query-параметры из spec."""
    out = {}
    for p in ep.params:
        if p["in"] == "query":
            val = p.get("example")
            if val is None:
                val = _example_from_schema({"type": p["type"],
                                             "format": p.get("format", "")})
            out[p["name"]] = val
    return out


def build_body(ep: Endpoint) -> tuple[dict, Any]:
    """Вернуть (headers, body) для запроса."""
    if not ep.body_schema:
        return {}, None
    ct = ep.body_schema.get("content_type", "application/json")
    schema = ep.body_schema.get("schema")
    example = ep.body_schema.get("example")
    body = example if example is not None else _example_from_schema(schema)
    return {"Content-Type": ct}, body


# ===========================================================================
# Базовые HTTP-обёртки
# ===========================================================================

def _request(method: str, url: str, headers: dict | None = None,
             params: dict | None = None, body: Any = None,
             content_type: str = "application/json",
             timeout: int = TIMEOUT,
             allow_redirects: bool = False) -> requests.Response | None:
    """Универсальный wrapper для запросов."""
    h = {"User-Agent": config.USER_AGENT}
    if headers:
        h.update(headers)
    kwargs: dict = {
        "timeout": timeout, "verify": False,
        "headers": h, "allow_redirects": allow_redirects,
    }
    if params:
        kwargs["params"] = params
    if body is not None:
        if content_type.startswith("application/json"):
            kwargs["json"] = body
        elif content_type.startswith("application/x-www-form-urlencoded"):
            kwargs["data"] = body if isinstance(body, dict) else str(body)
        elif content_type.startswith("application/xml"):
            kwargs["data"] = body if isinstance(body, str) else json.dumps(body)
            h["Content-Type"] = content_type
        elif content_type.startswith("text/plain"):
            kwargs["data"] = body if isinstance(body, str) else str(body)
            h["Content-Type"] = content_type
        else:
            kwargs["data"] = body if isinstance(body, str) else json.dumps(body)
    try:
        return requests.request(method, url, **kwargs)
    except requests.exceptions.Timeout:
        log.debug("timeout %s %s", method, url)
        return None
    except Exception as exc:  # noqa: BLE001
        log.debug("%s %s: %s", method, url, exc)
        return None


def test_endpoint(base: str, ep: Endpoint, headers: dict | None = None,
                  path_params: dict | None = None,
                  timeout: int = TIMEOUT) -> EndpointResult:
    """Отправить один endpoint и собрать результат."""
    url = build_request_url(base, ep, path_params)
    params = build_query_params(ep)
    extra_hdrs, body = build_body(ep)
    ct = extra_hdrs.get("Content-Type", "application/json")

    result = EndpointResult(method=ep.method, url=url)
    start = time.time()
    r = _request(ep.method, url, headers={**(extra_hdrs), **(headers or {})},
                 params=params or None, body=body, content_type=ct,
                 timeout=timeout)
    result.duration_ms = round((time.time() - start) * 1000, 1)
    if r is None:
        result.error = "timeout/error"
        return result
    result.status = r.status_code
    result.length = len(r.content)
    result.content_type = r.headers.get("Content-Type", "")[:80]
    result.response_snippet = r.text[:MAX_BODY_LOG]
    result.headers = dict(list(r.headers.items())[:20])
    return result


def fuzz_all(base: str, endpoints: list[Endpoint],
             headers: dict | None = None,
             threads: int = DEFAULT_THREADS,
             show_results: bool = True) -> list[EndpointResult]:
    """Отправить все endpoints параллельно."""
    if not endpoints:
        console.print("[yellow]Нет endpoints для fuzz.[/yellow]")
        return []

    console.print(f"[cyan]🚀 Fuzzing {len(endpoints)} endpoints "
                  f"(threads={threads})[/cyan]")

    results: list[EndpointResult] = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(test_endpoint, base, ep, headers): ep
                for ep in endpoints}
        with Progress(SpinnerColumn(),
                      TextColumn("[progress.description]{task.description}"),
                      BarColumn(),
                      TextColumn("{task.completed}/{task.total}"),
                      TimeElapsedColumn(),
                      console=console) as p:
            task = p.add_task("fuzz", total=len(endpoints))
            for f in as_completed(futs):
                p.advance(task)
                try:
                    results.append(f.result())
                except Exception as exc:  # noqa: BLE001
                    log.debug("fuzz: %s", exc)
    if show_results:
        _print_results(results)
    return results


def _print_results(results: list[EndpointResult]) -> None:
    if not results:
        console.print("[yellow]Нет результатов.[/yellow]")
        return
    table = Table(title=f"🌐 API Fuzz ({len(results)})")
    table.add_column("#", style="yellow", width=4)
    table.add_column("Method", style="magenta", width=7)
    table.add_column("Status", width=6)
    table.add_column("Len", style="cyan", width=8)
    table.add_column("ms", style="dim", width=7)
    table.add_column("URL", style="green", max_width=70)
    for i, r in enumerate(sorted(results, key=lambda x: (x.status, x.url)), 1):
        if r.error:
            table.add_row(str(i), r.method, "[red]err[/red]", "—", "—",
                          f"{r.url[:60]} ({r.error})")
            continue
        color = ("green" if 200 <= r.status < 300 else
                 "yellow" if 300 <= r.status < 400 else
                 "cyan" if 400 <= r.status < 500 else "red")
        table.add_row(str(i), r.method,
                      f"[{color}]{r.status}[/{color}]",
                      str(r.length), f"{r.duration_ms:.0f}",
                      r.url[:70])
    console.print(table)


# ===========================================================================
# Finding saver (интеграция с notes)
# ===========================================================================

def _save_finding(f: Finding, target: str) -> int:
    """Сохранить finding в notes (без падения, если модуль недоступен)."""
    try:
        from modules import notes
        nid = notes.add_note(
            kind="finding",
            title=f.title,
            target=target,
            severity=f.severity,
            status="open",
            tags=["api-fuzzer", f.kind],
            body=(
                f"**Kind:** {f.kind}\n"
                f"**URL:** {f.url or '—'}\n"
                f"**Method:** {f.method or '—'}\n\n"
                f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                f"**Data:** {json.dumps(f.data, ensure_ascii=False)[:1500]}"
            ),
        )
        return nid
    except Exception as exc:  # noqa: BLE001
        log.debug("save_finding: %s", exc)
        return -1


# ===========================================================================
# Auth-bypass matrix
# ===========================================================================

def auth_bypass_test(base: str, endpoints: list[Endpoint],
                     valid_auth: dict | None = None,
                     threads: int = DEFAULT_THREADS) -> list[Finding]:
    """
    Проверка обхода аутентификации:
        1. Без заголовков авторизации
        2. С пустым Bearer
        3. С мусорным токеном
        4. С токеном другого пользователя (если valid_auth задан)
    """
    console.print("[cyan]🔓 Auth-bypass matrix[/cyan]")
    auth_endpoints = [e for e in endpoints if e.auth_required]
    if not auth_endpoints:
        auth_endpoints = endpoints
        console.print("[yellow]В spec нет security — тестирую ВСЕ.[/yellow]")

    variants = [
        ("no-auth", {}),
        ("empty-bearer", {"Authorization": "Bearer "}),
        ("garbage-bearer", {"Authorization": "Bearer invalid.token.here"}),
        ("empty-basic", {"Authorization": "Basic "}),
        ("none-alg-jwt", {"Authorization": "Bearer eyJhbGciOiJub25lIn0."
                          "eyJzdWIiOiJhZG1pbiJ9."}),
    ]
    if valid_auth:
        variants.append(("foreign-token", valid_auth))

    findings: list[Finding] = []
    total = len(auth_endpoints) * len(variants)
    console.print(f"[dim]Проверяю {len(auth_endpoints)} × "
                  f"{len(variants)} = {total} комбинаций…[/dim]")

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("auth-bypass", total=total)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {}
            for ep in auth_endpoints:
                for name, hdrs in variants:
                    futs[ex.submit(test_endpoint, base, ep, hdrs)] = (ep, name)
            for fut in as_completed(futs):
                p.advance(task)
                ep, name = futs[fut]
                try:
                    r = fut.result()
                except Exception:
                    continue
                if r.status in (200, 201, 204, 206) and not r.error:
                    # Исключаем health-check endpoints
                    if any(k in r.url.lower() for k in
                           ("health", "ping", "status", "/version")):
                        continue
                    findings.append(Finding(
                        kind="auth_bypass",
                        severity="critical",
                        title=f"Auth bypass ({name}) on "
                              f"{ep.method} {ep.path}",
                        url=r.url, method=ep.method,
                        evidence=f"Status={r.status}, len={r.length}\n"
                                 f"{r.response_snippet[:300]}",
                        data={"variant": name, "status": r.status,
                              "content_type": r.content_type},
                    ))

    if findings:
        console.print(f"\n[bold red]⚠ Возможен auth bypass: "
                      f"{len(findings)}[/bold red]")
        t = Table(title="Auth-bypass findings")
        t.add_column("Method", style="magenta", width=7)
        t.add_column("URL", style="green", max_width=60)
        t.add_column("Variant", style="yellow", width=15)
        t.add_column("Status", width=7)
        for f in findings[:30]:
            t.add_row(f.method, f.url[:60],
                      f.data.get("variant", "?"),
                      str(f.data.get("status", "?")))
        console.print(t)
    else:
        console.print("[green]✓ Auth корректно требуется.[/green]")

    db.save_scan("api_auth_bypass", base, {
        "tested": total,
        "found": len(findings),
        "findings": [asdict(f) for f in findings],
    })
    return findings


# ===========================================================================
# HTTP method confusion
# ===========================================================================

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
             "OPTIONS", "TRACE", "CONNECT"]


def method_confusion_test(base: str, endpoints: list[Endpoint],
                          threads: int = DEFAULT_THREADS) -> list[Finding]:
    """
    Проверка альтернативных методов на «чужой» endpoint.
    Например PUT/DELETE, которые не указаны в spec, но работают.
    """
    console.print("[cyan]🔀 HTTP method confusion[/cyan]")
    findings: list[Finding] = []

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("methods", total=len(endpoints))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {}
            for ep in endpoints:
                for alt in _METHODS:
                    if alt == ep.method:
                        continue
                    alt_ep = Endpoint(method=alt, path=ep.path,
                                       params=ep.params,
                                       body_schema=ep.body_schema)
                    futs[ex.submit(test_endpoint, base, alt_ep)] = ep
            for fut in as_completed(futs):
                p.advance(task)
                ep = futs[fut]
                try:
                    r = fut.result()
                except Exception:
                    continue
                # Только «разрушительные» методы, которые внезапно работают
                if r.status in (200, 201, 202, 204) and not r.error:
                    if ep.method not in ("GET", "HEAD") and \
                       r.method in ("GET", "HEAD", "OPTIONS"):
                        continue
                    # OPTIONS — обычно отдаёт Allow, это не всегда находка
                    if r.method == "OPTIONS":
                        continue
                    if r.method in ("TRACE", "CONNECT") and r.status < 400:
                        findings.append(Finding(
                            kind="dangerous_method",
                            severity="high",
                            title=f"Dangerous method {r.method} allowed "
                                  f"on {ep.path}",
                            url=r.url, method=r.method,
                            evidence=f"Status={r.status}",
                            data={"endpoint_method": ep.method},
                        ))
                    elif r.method in ("PUT", "DELETE", "PATCH") and \
                            ep.method not in ("PUT", "DELETE", "PATCH"):
                        findings.append(Finding(
                            kind="method_confusion",
                            severity="medium",
                            title=f"Unexpected {r.method} allowed on "
                                  f"{ep.path} (spec: {ep.method})",
                            url=r.url, method=r.method,
                            evidence=f"Status={r.status}, len={r.length}",
                            data={"endpoint_method": ep.method,
                                  "tested": r.method},
                        ))

    # Дедуп по (method, path)
    seen = set()
    uniq: list[Finding] = []
    for f in findings:
        key = (f.method, f.url)
        if key not in seen:
            seen.add(key)
            uniq.append(f)

    if uniq:
        t = Table(title=f"Method confusion ({len(uniq)})")
        t.add_column("Method", style="magenta", width=8)
        t.add_column("URL", style="green", max_width=70)
        t.add_column("Sev", style="red", width=8)
        for f in uniq[:30]:
            t.add_row(f.method, f.url[:70], f.severity.upper())
        console.print(t)
    else:
        console.print("[green]✓ Все методы в норме.[/green]")

    db.save_scan("api_method_confusion", base, {
        "found": len(uniq),
        "findings": [asdict(f) for f in uniq],
    })
    return uniq


# ===========================================================================
# Content-Type confusion
# ===========================================================================

_CONTENT_TYPES = [
    ("application/json", None),
    ("application/xml", "<?xml version='1.0'?><root><test>1</test></root>"),
    ("application/x-www-form-urlencoded", "test=1&admin=true"),
    ("text/plain", "test"),
    ("application/yaml", "test: 1\nadmin: true"),
    ("application/x-www-form-urlencoded; charset=utf-16", "test=1"),
]


def content_type_test(base: str, endpoints: list[Endpoint],
                      threads: int = DEFAULT_THREADS) -> list[Finding]:
    """Проверка разных Content-Type на POST/PUT/PATCH."""
    console.print("[cyan]📝 Content-Type confusion[/cyan]")
    candidates = [e for e in endpoints
                  if e.method in ("POST", "PUT", "PATCH")]
    if not candidates:
        console.print("[yellow]Нет POST/PUT/PATCH endpoints.[/yellow]")
        return []

    findings: list[Finding] = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("ct", total=len(candidates) * len(_CONTENT_TYPES))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {}
            for ep in candidates:
                url = build_request_url(base, ep)
                for ctype, body in _CONTENT_TYPES:
                    futs[ex.submit(_request, ep.method, url,
                                    headers={"Content-Type": ctype},
                                    body=body, content_type=ctype)] = (ep, ctype)
            for fut in as_completed(futs):
                p.advance(task)
                ep, ctype = futs[fut]
                try:
                    r = fut.result()
                except Exception:
                    continue
                if r is None:
                    continue
                # Ошибка 500 = сервер упал на парсинге → потенциально интересно
                if r.status_code >= 500:
                    findings.append(Finding(
                        kind="content_type_dos",
                        severity="medium",
                        title=f"Server error on Content-Type "
                              f"{ctype} for {ep.method} {ep.path}",
                        url=build_request_url(base, ep),
                        method=ep.method,
                        evidence=f"Status={r.status_code}, "
                                 f"ctype={ctype}",
                        data={"content_type": ctype, "status": r.status_code},
                    ))
                elif r.status_code in (200, 201, 204) and ctype not in \
                        ("application/json",):
                    findings.append(Finding(
                        kind="content_type_confusion",
                        severity="low",
                        title=f"Accepts {ctype} on {ep.method} {ep.path}",
                        url=build_request_url(base, ep),
                        method=ep.method,
                        evidence=f"Status={r.status_code}, ctype={ctype}",
                        data={"content_type": ctype, "status": r.status_code},
                    ))

    if findings:
        t = Table(title=f"Content-Type findings ({len(findings)})")
        t.add_column("Method", style="magenta", width=7)
        t.add_column("URL", style="green", max_width=55)
        t.add_column("CT", style="yellow", max_width=30)
        t.add_column("Status", width=7)
        for f in findings[:30]:
            t.add_row(f.method, f.url[:55],
                      f.data.get("content_type", "?")[:30],
                      str(f.data.get("status", "?")))
        console.print(t)
    else:
        console.print("[green]✓ Content-Type confusion не найдена.[/green]")
    return findings


# ===========================================================================
# Mass assignment
# ===========================================================================

_MASS_ASSIGN_FIELDS = [
    {"role": "admin"},
    {"is_admin": True},
    {"isAdmin": True},
    {"admin": True},
    {"is_staff": True},
    {"is_superuser": True},
    {"verified": True},
    {"email_verified": True},
    {"balance": 999999},
    {"credits": 999999},
    {"permissions": ["*"]},
    {"scope": "admin"},
    {"user_id": 1},
    {"id": 1},
    {"status": "active"},
    {"status": "approved"},
    {"group": "admin"},
]


def mass_assignment_test(base: str, endpoints: list[Endpoint],
                         threads: int = DEFAULT_THREADS) -> list[Finding]:
    """Тест mass assignment через добавление скрытых полей в body."""
    console.print("[cyan]💉 Mass assignment[/cyan]")
    candidates = [e for e in endpoints
                  if e.method in ("POST", "PUT", "PATCH")
                  and e.body_schema]
    if not candidates:
        console.print("[yellow]Нет endpoint'ов с телом.[/yellow]")
        return []

    findings: list[Finding] = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("mass", total=len(candidates) * len(_MASS_ASSIGN_FIELDS))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {}
            for ep in candidates:
                url = build_request_url(base, ep)
                base_body = _example_from_schema(
                    (ep.body_schema or {}).get("schema")
                ) if ep.body_schema else {}
                if not isinstance(base_body, dict):
                    base_body = {"test": "value"}
                for extra in _MASS_ASSIGN_FIELDS:
                    injected = {**base_body, **extra}
                    futs[ex.submit(_request, ep.method, url,
                                    body=injected,
                                    content_type="application/json")] = (ep, extra)
            for fut in as_completed(futs):
                p.advance(task)
                ep, extra = futs[fut]
                try:
                    r = fut.result()
                except Exception:
                    continue
                if r is None:
                    continue
                if r.status_code in (200, 201, 204):
                    # Проверим, отразилось ли поле в ответе
                    snippet = r.text[:2000]
                    reflected = any(str(v).lower() in snippet.lower()
                                    for v in extra.values())
                    if reflected:
                        findings.append(Finding(
                            kind="mass_assignment",
                            severity="high",
                            title=f"Mass assignment: {list(extra.keys())[0]} "
                                  f"accepted on {ep.method} {ep.path}",
                            url=build_request_url(base, ep),
                            method=ep.method,
                            evidence=f"Injected: {extra}\n"
                                     f"Response: {snippet[:400]}",
                            data={"injected": extra,
                                  "status": r.status_code},
                        ))

    # Дедуп по URL + первое поле
    seen = set()
    uniq: list[Finding] = []
    for f in findings:
        key = (f.url, list(f.data.get("injected", {}).keys())[0]
               if f.data.get("injected") else "")
        if key not in seen:
            seen.add(key)
            uniq.append(f)

    if uniq:
        t = Table(title=f"Mass assignment findings ({len(uniq)})")
        t.add_column("Method", style="magenta", width=7)
        t.add_column("URL", style="green", max_width=55)
        t.add_column("Injected", style="yellow", max_width=30)
        for f in uniq[:30]:
            t.add_row(f.method, f.url[:55],
                      json.dumps(f.data.get("injected", {}), ensure_ascii=False)[:30])
        console.print(t)
    else:
        console.print("[green]✓ Mass assignment не найден.[/green]")
    return uniq


# ===========================================================================
# BOLA / IDOR matrix
# ===========================================================================

BOLA_ID_VALUES = [
    "1", "2", "3", "0", "-1", "999999", "9999999999",
    "00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000001",
    "admin", "me", "self", "null", "undefined", "*",
    "../../etc/passwd",
    "' OR '1'='1",
]


def bola_test(base: str, endpoint_path: str,
              id_param: str = "id",
              auth_header: dict | None = None,
              threads: int = DEFAULT_THREADS) -> list[Finding]:
    """
    Матрица по ID-параметру endpoint'а. Ищем аномалии:
        - слишком много 200 на разные ID
        - 200 на невалидные значения ('admin', '*' и т.д.)
        - разный размер body — потенциальный доступ к чужим данным
    """
    console.print(f"[cyan]🔓 BOLA/IDOR matrix: {endpoint_path} "
                  f"(param={id_param})[/cyan]")

    findings: list[Finding] = []
    results: list[tuple[str, int, int, str]] = []  # id, status, len, snippet

    def _one(val: str):
        url = urllib.parse.urljoin(
            base + "/",
            endpoint_path.replace(f"{{{id_param}}}", val).lstrip("/"),
        )
        if "{" not in endpoint_path and id_param not in endpoint_path:
            url = f"{url}?{id_param}={urllib.parse.quote(val)}"
        r = _request("GET", url, headers=auth_header)
        if r is None:
            return (val, 0, 0, "")
        return (val, r.status_code, len(r.content), r.text[:200])

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("bola", total=len(BOLA_ID_VALUES))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = [ex.submit(_one, v) for v in BOLA_ID_VALUES]
            for fut in as_completed(futs):
                p.advance(task)
                try:
                    results.append(fut.result())
                except Exception:
                    pass

    # Печать
    t = Table(title=f"BOLA: {endpoint_path}")
    t.add_column("ID", style="yellow", width=40)
    t.add_column("Status", width=7)
    t.add_column("Len", style="cyan", width=8)
    t.add_column("Snippet", style="dim", max_width=50)
    for val, status, length, snippet in results:
        color = ("green" if status == 200 else
                 "yellow" if status in (301, 302) else
                 "cyan" if 400 <= status < 500 else "red")
        t.add_row(val, f"[{color}]{status}[/{color}]",
                  str(length), snippet[:50].replace("\n", " "))
    console.print(t)

    # Анализ
    ok_ids = [r for r in results if r[1] == 200]
    if len(ok_ids) > 2:
        findings.append(Finding(
            kind="bola",
            severity="high",
            title=f"BOLA/IDOR: {len(ok_ids)} IDs returned 200 on "
                  f"{endpoint_path}",
            url=base + endpoint_path, method="GET",
            evidence=f"Valid IDs: {[r[0] for r in ok_ids][:10]}",
            data={"success_ids": [r[0] for r in ok_ids],
                  "count": len(ok_ids)},
        ))
    # Невалидные ID, которые вернули 200
    weird = [r for r in results
             if r[1] == 200 and r[0] in ("admin", "*", "me", "self",
                                          "null", "undefined",
                                          "-1", "9999999999")]
    if weird:
        findings.append(Finding(
            kind="bola",
            severity="critical",
            title=f"BOLA/IDOR: magic IDs accepted ({len(weird)}) "
                  f"on {endpoint_path}",
            url=base + endpoint_path, method="GET",
            evidence=", ".join(r[0] for r in weird),
            data={"magic_ids": [r[0] for r in weird]},
        ))

    if not findings:
        console.print("[green]✓ BOLA/IDOR явных признаков нет.[/green]")
    db.save_scan("api_bola", endpoint_path, {
        "results": [{"id": r[0], "status": r[1], "len": r[2]}
                    for r in results],
        "findings": [asdict(f) for f in findings],
    })
    return findings


# ===========================================================================
# SSRF-параметры
# ===========================================================================

SSRF_PARAM_NAMES = [
    "url", "uri", "link", "redirect", "redirect_uri", "next", "target",
    "callback", "webhook", "endpoint", "host", "site", "return", "return_url",
    "continue", "dest", "destination", "domain", "feed", "fetch",
    "load", "open", "source", "src", "to", "u",
]


def ssrf_param_test(base: str, endpoints: list[Endpoint],
                    collaborator: str = "http://collab.example.com",
                    threads: int = DEFAULT_THREADS) -> list[Finding]:
    """Тест SSRF через типовые имена query/body-параметров."""
    console.print(f"[cyan]🎯 SSRF param test "
                  f"(collab={collaborator})[/cyan]")
    findings: list[Finding] = []

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("ssrf", total=len(endpoints))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {}
            for ep in endpoints:
                url = build_request_url(base, ep)
                for pname in SSRF_PARAM_NAMES:
                    if ep.method == "GET":
                        futs[ex.submit(_request, "GET", url,
                                        params={pname: collaborator})] = (ep, pname)
                    elif ep.method in ("POST", "PUT", "PATCH"):
                        body = {pname: collaborator}
                        futs[ex.submit(_request, ep.method, url,
                                        body=body)] = (ep, pname)
            for fut in as_completed(futs):
                p.advance(task)
                ep, pname = futs[fut]
                try:
                    r = fut.result()
                except Exception:
                    continue
                if r is None:
                    continue
                # Признаки SSRF: сервер сам пошёл по нашему URL
                #   - ответ содержит наш collaborator
                #   - ответ содержит типовые ошибки URL fetch
                #   - ответ 200 при передаче внешнего URL
                body = r.text.lower()
                if collaborator.lower() in body:
                    findings.append(Finding(
                        kind="ssrf",
                        severity="high",
                        title=f"SSRF reflected via param '{pname}' "
                              f"on {ep.method} {ep.path}",
                        url=build_request_url(base, ep), method=ep.method,
                        evidence=f"Param={pname}, "
                                 f"collaborator reflected in response",
                        data={"param": pname, "status": r.status_code},
                    ))
                elif r.status_code == 200 and pname in ("url", "uri",
                                                          "callback", "webhook") \
                        and len(r.content) > 0:
                    findings.append(Finding(
                        kind="ssrf_suspect",
                        severity="medium",
                        title=f"Possible SSRF via param '{pname}' on "
                              f"{ep.method} {ep.path} (200)",
                        url=build_request_url(base, ep), method=ep.method,
                        evidence=f"Param={pname}, status=200",
                        data={"param": pname, "status": r.status_code},
                    ))

    # Дедуп
    seen = set()
    uniq: list[Finding] = []
    for f in findings:
        k = (f.url, f.data.get("param"))
        if k not in seen:
            seen.add(k)
            uniq.append(f)

    if uniq:
        t = Table(title=f"SSRF suspects ({len(uniq)})")
        t.add_column("Method", style="magenta", width=7)
        t.add_column("URL", style="green", max_width=55)
        t.add_column("Param", style="yellow", width=15)
        t.add_column("Kind", width=15)
        for f in uniq[:30]:
            t.add_row(f.method, f.url[:55],
                      f.data.get("param", "?"), f.kind)
        console.print(t)
    else:
        console.print("[green]✓ SSRF suspects нет.[/green]")
    return uniq


# ===========================================================================
# ReDoS (regex DoS)
# ===========================================================================

REDOS_PAYLOADS = [
    "a" * 5000,
    "a" * 50000,
    ("a" * 5000) + "!",
    "1" * 10000,
    ("0" * 2000) + "x",
    ("(" * 500) + "a" + (")" * 500),
    "AAA" * 5000,
    "!@#$%^&*()" * 500,
]


def redos_test(base: str, endpoints: list[Endpoint],
               threads: int = 5) -> list[Finding]:
    """
    Отправляем потенциально катастрофические payload'ы.
    Ищем аномально долгие ответы (>3x baseline).
    """
    console.print("[cyan]🧨 ReDoS test[/cyan]")
    findings: list[Finding] = []
    candidates = [e for e in endpoints if e.params or e.method == "GET"]
    if not candidates:
        return []

    # Baseline
    baseline_ms: dict[str, float] = {}
    for ep in candidates[:15]:
        r = test_endpoint(base, ep)
        if not r.error and r.duration_ms > 0:
            baseline_ms[ep.method + ep.path] = r.duration_ms

    console.print(f"[dim]Baseline: {len(baseline_ms)} endpoints[/dim]")

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("redos", total=len(candidates) * len(REDOS_PAYLOADS))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {}
            for ep in candidates:
                url = build_request_url(base, ep)
                # baseline для endpoint'а
                base_ms = baseline_ms.get(ep.method + ep.path, 200.0)
                for payload in REDOS_PAYLOADS:
                    # подставляем в первый query-параметр
                    params = {ep.params[0]["name"]: payload} \
                        if (ep.params and ep.params[0]["in"] == "query") \
                        else {"q": payload}
                    futs[ex.submit(_request, ep.method, url,
                                    params=params,
                                    timeout=20)] = (ep, payload, base_ms)
            for fut in as_completed(futs):
                p.advance(task)
                ep, payload, base_ms = futs[fut]
                try:
                    start = time.time()
                    r = fut.result()
                    dur = (time.time() - start) * 1000
                except Exception:
                    continue
                if r is None:
                    continue
                # аномалия: > 5x baseline и > 2000ms
                if dur > max(base_ms * 5, 2000):
                    findings.append(Finding(
                        kind="redos",
                        severity="medium",
                        title=f"ReDoS-suspect on {ep.method} {ep.path} "
                              f"({dur:.0f}ms vs baseline {base_ms:.0f}ms)",
                        url=build_request_url(base, ep), method=ep.method,
                        evidence=f"Payload length={len(payload)}, "
                                 f"duration={dur:.0f}ms",
                        data={"duration_ms": round(dur, 1),
                              "baseline_ms": round(base_ms, 1),
                              "payload_len": len(payload)},
                    ))
                    break   # один finding на endpoint достаточно

    if findings:
        t = Table(title=f"ReDoS suspects ({len(findings)})")
        t.add_column("Method", style="magenta", width=7)
        t.add_column("URL", style="green", max_width=55)
        t.add_column("ms", style="red", width=8)
        for f in findings[:20]:
            t.add_row(f.method, f.url[:55],
                      str(int(f.data.get("duration_ms", 0))))
        console.print(t)
    else:
        console.print("[green]✓ ReDoS не обнаружен.[/green]")
    return findings


# ===========================================================================
# Idempotency / race condition
# ===========================================================================

def idempotency_test(base: str, endpoints: list[Endpoint],
                     threads: int = 20) -> list[Finding]:
    """
    Отправляем 10 одинаковых POST/PUT запросов параллельно.
    Если большинство прошло (200/201) — возможен race/отсутствие idempotency.
    """
    console.print("[cyan]⚡ Idempotency/race test[/cyan]")
    candidates = [e for e in endpoints
                  if e.method in ("POST", "PUT")]
    if not candidates:
        console.print("[yellow]Нет POST/PUT endpoints.[/yellow]")
        return []

    findings: list[Finding] = []
    parallel = 10
    for ep in candidates[:10]:   # ограничимся 10 endpoints
        url = build_request_url(base, ep)
        _, body = build_body(ep)
        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futs = [ex.submit(_request, ep.method, url, body=body)
                    for _ in range(parallel)]
            results = []
            for f in as_completed(futs):
                try:
                    r = f.result()
                    if r is not None:
                        results.append(r.status_code)
                except Exception:
                    pass
        ok = sum(1 for s in results if s in (200, 201, 202, 204))
        # Если ≥ 8 из 10 прошло — подозрительно
        if ok >= 8:
            findings.append(Finding(
                kind="idempotency",
                severity="medium",
                title=f"Non-idempotent {ep.method} {ep.path} "
                      f"({ok}/{parallel} accepted)",
                url=url, method=ep.method,
                evidence=f"{ok} из {parallel} одновременных запросов "
                         f"прошли успешно",
                data={"success": ok, "total": parallel},
            ))

    if findings:
        t = Table(title=f"Idempotency suspects ({len(findings)})")
        t.add_column("Method", style="magenta", width=7)
        t.add_column("URL", style="green", max_width=60)
        t.add_column("OK/Total", style="yellow", width=10)
        for f in findings:
            t.add_row(f.method, f.url[:60],
                      f"{f.data['success']}/{f.data['total']}")
        console.print(t)
    else:
        console.print("[green]✓ Idempotency в норме.[/green]")
    return findings


# ===========================================================================
# Rate-limit tester (адаптивный, с burst detection)
# ===========================================================================

def rate_limit_test(url: str, requests_count: int = 100,
                    delay: float = 0.0, method: str = "GET",
                    burst_size: int = 10) -> dict:
    """
    Адаптивный тест rate-limit:
        - нормальный режим
        - burst-режим (burst_size запросов подряд без паузы)
    """
    console.print(f"[cyan]⏱  Rate-limit: {url} "
                  f"({requests_count} req, delay={delay}s, "
                  f"burst={burst_size})[/cyan]")

    statuses: list[int] = []
    durations: list[float] = []
    statuses_burst: list[int] = []
    start = time.time()

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("normal", total=requests_count)
        for _ in range(requests_count):
            t0 = time.time()
            r = _request(method, url, timeout=TIMEOUT)
            statuses.append(r.status_code if r else 0)
            durations.append(time.time() - t0)
            p.advance(task)
            if delay:
                time.sleep(delay)

        # Burst
        task2 = p.add_task("burst", total=burst_size)
        with ThreadPoolExecutor(max_workers=burst_size) as ex:
            futs = [ex.submit(_request, method, url, timeout=TIMEOUT)
                    for _ in range(burst_size)]
            for f in as_completed(futs):
                p.advance(task2)
                try:
                    r = f.result()
                    statuses_burst.append(r.status_code if r else 0)
                except Exception:
                    statuses_burst.append(0)

    total_time = time.time() - start
    counter = {}
    for s in statuses:
        counter[s] = counter.get(s, 0) + 1
    burst_counter = {}
    for s in statuses_burst:
        burst_counter[s] = burst_counter.get(s, 0) + 1

    result = {
        "url": url,
        "total_requests": requests_count,
        "duration_sec": round(total_time, 2),
        "rps": round(requests_count / max(total_time, 0.001), 2),
        "avg_ms": round(sum(durations) / max(len(durations), 1) * 1000, 1),
        "statuses": counter,
        "burst_statuses": burst_counter,
        "rate_limited_normal": 429 in counter,
        "rate_limited_burst": 429 in burst_counter,
    }

    t = Table(title=f"Rate-limit: {url[:60]}")
    t.add_column("Метрика", style="cyan")
    t.add_column("Значение", style="green")
    for k in ("total_requests", "duration_sec", "rps", "avg_ms"):
        t.add_row(k, str(result[k]))
    console.print(t)

    st = Table(title="Statuses (normal / burst)")
    st.add_column("Code", style="magenta", width=8)
    st.add_column("Normal", style="green", width=10)
    st.add_column("Burst", style="yellow", width=10)
    all_codes = set(counter) | set(burst_counter)
    for code in sorted(all_codes):
        st.add_row(str(code), str(counter.get(code, 0)),
                   str(burst_counter.get(code, 0)))
    console.print(st)

    if 429 in counter or 429 in burst_counter:
        console.print("[green]✓ Rate-limit активен.[/green]")
    else:
        console.print("[red]⚠ 429 не получен — rate-limit может "
                      "отсутствовать![/red]")

    db.save_scan("api_ratelimit", url, result)
    return result


# ===========================================================================
# JWT-атаки (базовые, полноценный suite — в jwt_suite.py)
# ===========================================================================

def _b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    import base64
    return base64.urlsafe_b64decode(s)


def _b64url_encode(b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt_basic_test(base: str, endpoints: list[Endpoint],
                   valid_token: str = "",
                   threads: int = DEFAULT_THREADS) -> list[Finding]:
    """
    Проверяет принимает ли API JWT с alg:none.
    """
    console.print("[cyan]🔑 JWT alg:none test[/cyan]")
    candidates = [e for e in endpoints if e.auth_required]
    if not candidates:
        candidates = endpoints

    # Форжим токен с alg=none
    import base64
    header = _b64url_encode(json.dumps({"alg": "none",
                                         "typ": "JWT"}).encode())
    payload = _b64url_encode(json.dumps({"sub": "admin",
                                          "role": "admin",
                                          "exp": 9999999999}).encode())
    forged = f"{header}.{payload}."

    findings: list[Finding] = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  console=console) as p:
        task = p.add_task("jwt", total=len(candidates))
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {}
            for ep in candidates:
                futs[ex.submit(test_endpoint, base, ep,
                                {"Authorization": f"Bearer {forged}"})] = ep
            for fut in as_completed(futs):
                p.advance(task)
                ep = futs[fut]
                try:
                    r = fut.result()
                except Exception:
                    continue
                if r.status in (200, 201, 204) and not r.error:
                    findings.append(Finding(
                        kind="jwt_none_accepted",
                        severity="critical",
                        title=f"JWT alg:none accepted on "
                              f"{ep.method} {ep.path}",
                        url=r.url, method=ep.method,
                        evidence=f"Status={r.status}",
                        data={"status": r.status},
                    ))

    if findings:
        console.print(f"[bold red]⚠ JWT alg:none принят: "
                      f"{len(findings)}[/bold red]")
    else:
        console.print("[green]✓ JWT alg:none отвергнут.[/green]")
    return findings


# ===========================================================================
# GraphQL — расширенный
# ===========================================================================

GQL_INTROSPECTION = """{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name
      fields {
        name
        type { kind name ofType { kind name } }
      }
    }
  }
}"""

GQL_DEPTH = """{
  __schema {
    types { fields { type { fields { type { fields { type { name } } } } } } }
  }
}"""

GQL_ALIAS_BOMB = "{\n  " + "\n  ".join(f"a{i}: __typename"
                                         for i in range(100)) + "\n}"


def graphql_fuzz(url: str, query: str, variables: dict | None = None,
                 timeout: int = TIMEOUT) -> dict:
    """Отправить один GraphQL-запрос."""
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    start = time.time()
    r = _request("POST", url, body=payload,
                 content_type="application/json", timeout=timeout)
    dur = (time.time() - start) * 1000
    if r is None:
        console.print("[red]Ошибка GraphQL-запроса.[/red]")
        return {}
    result = {
        "url": url,
        "status": r.status_code,
        "length": len(r.content),
        "duration_ms": round(dur, 1),
        "response": r.text[:800],
    }
    console.print(f"[{'green' if r.status_code == 200 else 'red'}]"
                  f"{r.status_code}[/] {len(r.content)}B "
                  f"[dim]{dur:.0f}ms[/dim]")
    return result


def graphql_scan(url: str) -> dict:
    """Полный GraphQL-скан."""
    console.print(f"[cyan]🔎 GraphQL scan: {url}[/cyan]")
    result: dict = {"url": url, "findings": []}

    # 1. Introspection
    console.print("\n[bold cyan]1. Introspection[/bold cyan]")
    r1 = graphql_fuzz(url, GQL_INTROSPECTION)
    if "__schema" in r1.get("response", ""):
        console.print("[red]⚠ Introspection включён![/red]")
        result["introspection_enabled"] = True
        result["findings"].append(Finding(
            kind="graphql_introspection",
            severity="medium",
            title=f"GraphQL introspection enabled at {url}",
            url=url, method="POST",
            evidence="Ответ содержит __schema",
            data={"url": url},
        ))

    # 2. Depth attack
    console.print("\n[bold cyan]2. Depth attack[/bold cyan]")
    r2 = graphql_fuzz(url, GQL_DEPTH)
    if r2.get("duration_ms", 0) > 3000:
        result["findings"].append(Finding(
            kind="graphql_depth_dos",
            severity="medium",
            title=f"GraphQL depth attack slowed server "
                  f"({r2.get('duration_ms'):.0f}ms)",
            url=url, method="POST",
            evidence=f"duration={r2.get('duration_ms')}ms",
            data=r2,
        ))

    # 3. Alias bomb
    console.print("\n[bold cyan]3. Alias bomb (100 алиасов)[/bold cyan]")
    r3 = graphql_fuzz(url, GQL_ALIAS_BOMB)
    if r3.get("status") == 200:
        result["findings"].append(Finding(
            kind="graphql_alias_amplification",
            severity="medium",
            title="GraphQL alias amplification possible",
            url=url, method="POST",
            evidence=f"100 алиасов обработано, "
                     f"{r3.get('duration_ms'):.0f}ms",
            data=r3,
        ))

    db.save_scan("graphql_scan", url, result)
    return result


# ===========================================================================
# Экспорт
# ===========================================================================

def export_json(base: str, results: list[EndpointResult],
                findings: list[Finding] | None = None,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:40]
        path = str(API_DIR / f"fuzz_{safe}_{ts}.json")
    try:
        data = {
            "base": base,
            "ts": datetime.now().isoformat(),
            "results": [asdict(r) for r in results],
            "findings": [asdict(f) for f in (findings or [])],
        }
        Path(path).write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]✓ JSON: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка JSON: {exc}[/red]")
        return None


def export_csv(results: list[EndpointResult],
               path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = str(API_DIR / f"fuzz_{ts}.csv")
    cols = ["method", "url", "status", "length", "content_type",
            "duration_ms", "error"]
    try:
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for r in results:
                w.writerow(asdict(r))
        console.print(f"[green]✓ CSV: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка CSV: {exc}[/red]")
        return None


def export_html(base: str, results: list[EndpointResult],
                findings: list[Finding] | None = None,
                path: str | None = None) -> Path | None:
    if not path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", base)[:40]
        path = str(API_DIR / f"report_{safe}_{ts}.html")

    findings = findings or []

    html = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>API Fuzz — {html_mod.escape(base)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.5;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;padding-bottom:8px;}",
        "h2{color:#00ff9c;margin-top:32px;border-left:4px solid #00ff9c;"
        "padding-left:12px;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;text-align:left;padding:8px;"
        "border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;vertical-align:top;"
        "word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".crit{color:#ff4040;font-weight:bold;}",
        ".high{color:#ff7a40;font-weight:bold;}",
        ".med{color:#ffd23f;}",
        ".low{color:#00ff9c;}",
        ".info{color:#7ad9ff;}",
        ".ok{color:#00ff9c;}",
        ".err{color:#ff4040;}",
        "pre{background:#050505;border:1px solid #222;padding:8px;"
        "overflow-x:auto;color:#a0ffa0;font-size:11px;max-height:300px;}",
        "</style></head><body>",
        f"<h1>🌐 API Fuzz Report</h1>",
        f"<p><b>Base:</b> {html_mod.escape(base)}<br>"
        f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>"
        f"<b>Endpoints tested:</b> {len(results)}<br>"
        f"<b>Findings:</b> {len(findings)}</p>",
    ]

    # Findings
    if findings:
        html.append(f"<h2>🚨 Findings ({len(findings)})</h2>")
        for f in findings:
            html.append(f"<div style='border-left:4px solid "
                        f"#ff4040;padding:12px;margin:12px 0;"
                        f"background:#0d0d0d;'>")
            html.append(f"<div><b class='{f.severity}'>"
                        f"[{f.severity.upper()}]</b> "
                        f"<b>{html_mod.escape(f.title)}</b></div>")
            html.append(f"<div><b>Kind:</b> {html_mod.escape(f.kind)} | "
                        f"<b>Method:</b> {html_mod.escape(f.method)} | "
                        f"<b>URL:</b> <a style='color:#7ad9ff;' "
                        f"href='{html_mod.escape(f.url)}'>"
                        f"{html_mod.escape(f.url[:120])}</a></div>")
            if f.evidence:
                html.append(f"<pre>{html_mod.escape(f.evidence[:1000])}</pre>")
            if f.data:
                html.append(f"<div style='color:#888;font-size:11px;'>"
                            f"data: {html_mod.escape(json.dumps(f.data, ensure_ascii=False))[:500]}"
                            f"</div>")
            html.append("</div>")

    # Endpoints
    html.append(f"<h2>📋 Endpoints ({len(results)})</h2>")
    html.append("<table><tr><th>Method</th><th>URL</th><th>Status</th>"
                "<th>Len</th><th>ms</th><th>CT</th></tr>")
    for r in sorted(results, key=lambda x: (x.status, x.url)):
        if r.error:
            html.append(f"<tr><td>{r.method}</td>"
                        f"<td>{html_mod.escape(r.url)}</td>"
                        f"<td class='err'>err</td><td colspan='3'>"
                        f"{html_mod.escape(r.error)}</td></tr>")
            continue
        color = ("ok" if 200 <= r.status < 300 else
                 "med" if 300 <= r.status < 400 else
                 "info" if 400 <= r.status < 500 else "err")
        html.append(
            f"<tr><td>{r.method}</td>"
            f"<td>{html_mod.escape(r.url[:120])}</td>"
            f"<td class='{color}'>{r.status}</td>"
            f"<td>{r.length}</td><td>{r.duration_ms:.0f}</td>"
            f"<td>{html_mod.escape(r.content_type[:40])}</td></tr>"
        )
    html.append("</table></body></html>")

    try:
        Path(path).write_text("\n".join(html), encoding="utf-8")
        console.print(f"[green]✓ HTML: {path}[/green]")
        return Path(path)
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка HTML: {exc}[/red]")
        return None


# ===========================================================================
# Высокоуровневый сценарий
# ===========================================================================

def full_scan(spec_path: str, base_url: str = "",
              auth_header: str = "",
              run_advanced: bool = True) -> dict:
    """
    Полный скан API:
        1. Загрузка spec (openapi/postman/har)
        2. Fuzz всех endpoints
        3. Advanced тесты (auth bypass, method confusion,
           content-type, mass assign, SSRF, JWT)
        4. Findings → notes
        5. Экспорт JSON + CSV + HTML
    """
    # Detect spec type
    spec = None
    lower = spec_path.lower()
    if lower.endswith(".json") or lower.endswith(".yaml") or \
            lower.endswith(".yml") or spec_path.startswith(("http://", "https://")):
        spec = load_openapi(spec_path)
    elif "postman" in lower:
        spec = load_postman(spec_path)
    elif lower.endswith(".har"):
        spec = load_har(spec_path)

    if not spec:
        # auto-detection
        console.print("[yellow]Пробую авто-детект формата…[/yellow]")
        spec = load_openapi(spec_path) or load_postman(spec_path) or \
               load_har(spec_path)

    if not spec:
        console.print("[red]Не удалось загрузить spec.[/red]")
        return {}

    endpoints = parse_endpoints(spec)
    console.print(f"[green]Найдено endpoints: {len(endpoints)}[/green]")
    if not endpoints:
        console.print("[yellow]Endpoints не найдены в spec.[/yellow]")
        return {}

    base = base_url or get_base_url(spec)
    if not base:
        console.print("[red]Не удалось определить base URL. "
                      "Укажи --base-url.[/red]")
        return {}
    if not confirm_external(base):
        return {}

    headers = {}
    if auth_header:
        k, _, v = auth_header.partition(":")
        if k.strip() and v.strip():
            headers[k.strip()] = v.strip()

    # 1. Basic fuzz
    results = fuzz_all(base, endpoints, headers=headers)

    # 2. Advanced тесты
    all_findings: list[Finding] = []
    if run_advanced and endpoints:
        console.print("\n[bold cyan]═══ Advanced tests ═══[/bold cyan]")
        all_findings.extend(auth_bypass_test(base, endpoints, headers))
        all_findings.extend(method_confusion_test(base, endpoints))
        all_findings.extend(content_type_test(base, endpoints))
        all_findings.extend(mass_assignment_test(base, endpoints))
        all_findings.extend(jwt_basic_test(base, endpoints))

    # 3. Findings → notes
    saved = 0
    for f in all_findings:
        nid = _save_finding(f, target=base)
        if nid > 0:
            saved += 1
    if saved:
        console.print(f"[green]✓ Findings сохранены в notes: {saved}"
                      f"[/green]")

    # 4. Экспорт
    export_json(base, results, all_findings)
    export_csv(results)
    export_html(base, results, all_findings)

    # 5. Notify
    try:
        from modules import notifier
        notifier.notify_all(
            f"🌐 API Fuzz: {base}",
            f"Endpoints: {len(results)}\n"
            f"Findings: {len(all_findings)}",
        )
    except Exception:
        pass

    db.save_scan("api_full_scan", base, {
        "endpoints": len(endpoints),
        "results": len(results),
        "findings": len(all_findings),
    })
    return {
        "base": base,
        "endpoints": len(endpoints),
        "results": results,
        "findings": all_findings,
    }


# ===========================================================================
# CLI-обёртки (совместимы со старыми названиями)
# ===========================================================================

def cli_scan(spec_path: str, base_url: str = "",
             auth_header: str = "") -> None:
    """CLI: полный скан."""
    full_scan(spec_path, base_url, auth_header)


def cli_ratelimit(url: str, count: int = 100) -> None:
    rate_limit_test(url, count)


def cli_graphql(url: str) -> None:
    graphql_scan(url)


def cli_bola(base: str, endpoint: str, param: str = "id") -> None:
    bola_test(base, endpoint, param)


def cli_discover(base_url: str) -> None:
    """Auto-discovery OpenAPI."""
    spec = discover_openapi(base_url)
    if spec:
        endpoints = parse_endpoints(spec)
        console.print(f"[green]Найдено endpoints: {len(endpoints)}[/green]")


# ===========================================================================
# Меню (совместимо со старым)
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🌐 API Fuzzing Suite[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан (OpenAPI/Postman/HAR + advanced)"),
        ("2", "Auto-discovery OpenAPI по типовым путям"),
        ("3", "Fuzz endpoints из spec (base)"),
        ("4", "Auth-bypass matrix"),
        ("5", "HTTP method confusion"),
        ("6", "Content-Type confusion"),
        ("7", "Mass assignment"),
        ("8", "SSRF param test"),
        ("9", "ReDoS test"),
        ("10", "Idempotency / race condition"),
        ("11", "JWT alg:none test"),
        ("12", "BOLA / IDOR matrix"),
        ("13", "Rate-limit tester"),
        ("14", "GraphQL scan"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    console.print("[yellow]⚠ Только для авторизованного пентеста.[/yellow]")
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        spec = Prompt.ask("Путь к spec (файл / URL)")
        base = Prompt.ask("Base URL (пусто = из spec)", default="")
        auth = Prompt.ask("Auth header (напр. 'Authorization: Bearer xxx', "
                          "пусто = нет)", default="")
        full_scan(spec, base, auth)
    elif c == "2":
        base = Prompt.ask("Base URL")
        cli_discover(base)
    elif c == "3":
        spec_path = Prompt.ask("Путь к spec")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                fuzz_all(base, endpoints)
    elif c == "4":
        spec_path = Prompt.ask("Путь к spec")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                auth_bypass_test(base, endpoints)
    elif c == "5":
        spec_path = Prompt.ask("Путь к spec")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                method_confusion_test(base, endpoints)
    elif c == "6":
        spec_path = Prompt.ask("Путь к spec")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                content_type_test(base, endpoints)
    elif c == "7":
        spec_path = Prompt.ask("Путь к spec")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                mass_assignment_test(base, endpoints)
    elif c == "8":
        spec_path = Prompt.ask("Путь к spec")
        collab = Prompt.ask("Collaborator URL",
                            default="http://collab.example.com")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                ssrf_param_test(base, endpoints, collab)
    elif c == "9":
        spec_path = Prompt.ask("Путь к spec")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                redos_test(base, endpoints)
    elif c == "10":
        spec_path = Prompt.ask("Путь к spec")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                idempotency_test(base, endpoints)
    elif c == "11":
        spec_path = Prompt.ask("Путь к spec")
        spec = load_openapi(spec_path)
        if spec:
            endpoints = parse_endpoints(spec)
            base = get_base_url(spec) or Prompt.ask("Base URL")
            if confirm_external(base):
                jwt_basic_test(base, endpoints)
    elif c == "12":
        base = Prompt.ask("Base URL")
        endpoint = Prompt.ask("Endpoint path (напр. /api/v1/orders/{id})")
        param = Prompt.ask("Параметр", default="id")
        bola_test(base, endpoint, param)
    elif c == "13":
        url = Prompt.ask("URL")
        count = IntPrompt.ask("Запросов", default=100)
        delay = float(Prompt.ask("Delay (сек)", default="0"))
        rate_limit_test(url, count, delay)
    elif c == "14":
        graphql_scan(Prompt.ask("GraphQL endpoint"))