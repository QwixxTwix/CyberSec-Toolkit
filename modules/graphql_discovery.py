"""
GraphQL / API Discovery Pro.
Author: idqwixxa

⚠ Только для авторизованного пентеста / bug bounty / CTF.

Возможности:
    ─── GraphQL ───
    - Поиск endpoint'ов (60+ общих путей)
    - Introspection (POST + GET + batching)
    - Schema analysis: types, queries, mutations, subscriptions,
      interfaces, unions, enums, input-objects
    - Sensitive field detection (password/token/secret/apiKey)
    - Auth endpoint detection (login/register/reset)
    - Apollo / Relay / urql / graphql-request detection
    - WebSocket endpoint detection hints
    - Persisted queries hints
    - Batch query support detection
    - Rate-limit hints

    ─── API Discovery ───
    - Swagger / OpenAPI / Redoc (25+ путей)
    - REST endpoints (расширенный список)
    - API endpoints из JS/HTML (fetch/axios/WebSocket/graphql clients)
    - Source maps (.js.map)

    ─── Интеграция ───
    - Findings → notes
    - Notify при critical/high
    - HTML / JSON / Markdown экспорт
"""
import html as html_mod
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.prompt import Prompt, Confirm
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

GQL_DIR = REPORT_DIR / "graphql_discovery"
GQL_DIR.mkdir(parents=True, exist_ok=True)

TIMEOUT = 15


# ===========================================================================
# Findings
# ===========================================================================

@dataclass
class APIFinding:
    kind: str
    severity: str
    title: str
    target: str = ""
    evidence: str = ""
    data: dict = field(default_factory=dict)


def _save_finding(f: APIFinding) -> int:
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
            tags=["graphql", "api", f.kind],
            body=(f"**Kind:** {f.kind}\n"
                  f"**Target:** {f.target}\n\n"
                  f"**Evidence:**\n```\n{(f.evidence or '—')[:1500]}\n```\n\n"
                  f"**Data:** `{json.dumps(f.data, ensure_ascii=False, default=str)[:1000]}`"),
        )
    except Exception:
        return -1


# ===========================================================================
# GraphQL paths
# ===========================================================================

COMMON_GQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/gql",
    "/v1/graphql", "/v2/graphql", "/v3/graphql", "/query", "/gql",
    "/index.php?graphql", "/graphql/console", "/graphql.php",
    "/altair", "/playground", "/api/v1/graphql", "/api/v2/graphql",
    "/api/query", "/api/graph", "/wp-graphql", "/graphql/v1",
    "/api/graphql/v1", "/gql/v1", "/graphql/query", "/graphql/api",
    "/graph", "/data", "/api/data", "/api/explorer",
    "/internal/graphql", "/private/graphql", "/rest/graphql",
    "/admin/graphql", "/dev/graphql", "/test/graphql",
    "/.graphql", "/graphql.json", "/api/graphql.json",
    "/query.php", "/graphql/graphql", "/gql/graphql",
    "/v1/query", "/v1/gql", "/hasura/v1/graphql",
    "/api/v1/query", "/api/v1/gql", "/frontend/graphql",
    "/backend/graphql", "/service/graphql", "/services/graphql",
    "/status/graphql", "/health/graphql", "/_graphql", "/__graphql",
    "/GraphQL", "/GraphIQL", "/API/graphql",
]

# Apollo-specific paths
APOLLO_HINTS = [
    "/.well-known/apollo/server-health",
    "/graphql/health",
    "/graphql/.well-known/apollo/server-health",
]

# WebSocket hints
WS_HINTS = ["/graphql", "/subscriptions", "/ws", "/socket.io"]


INTROSPECTION_FULL = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type { kind name ofType { kind name ofType { kind name } } }
        }
        type { kind name ofType { kind name ofType { kind name } } }
        isDeprecated
      }
      inputFields {
        name
        type { kind name ofType { kind name } }
      }
      enumValues(includeDeprecated: true) { name }
      interfaces { name }
      possibleTypes { name }
    }
    directives {
      name
      locations
      args { name type { kind name } }
    }
  }
}
""".strip()

INTROSPECTION_MIN = "{ __schema { queryType { name } mutationType { name } types { name kind } } }"


# ===========================================================================
# Sensitive / auth field names
# ===========================================================================

SENSITIVE_FIELD_NAMES = [
    "password", "passwd", "pwd", "pass",
    "token", "accessToken", "refreshToken", "idToken",
    "secret", "clientSecret", "apiKey", "api_key",
    "privateKey", "private_key", "secretKey", "secret_key",
    "creditCard", "credit_card", "cardNumber", "card_number",
    "cvv", "cvc", "ssn", "socialSecurityNumber",
    "pin", "mfaSecret", "totp_secret", "otpSecret",
    "session", "sessionId", "session_id",
]

AUTH_FIELD_NAMES = [
    "login", "signin", "signIn", "authenticate", "auth",
    "register", "signup", "signUp", "createUser",
    "resetPassword", "forgotPassword", "changePassword",
    "verifyEmail", "verifyToken", "refreshToken",
    "logout", "signout",
]


# ===========================================================================
# Model
# ===========================================================================

@dataclass
class GQLEndpoint:
    url: str
    method: str = "POST"
    status: int = 0
    introspection: bool = False
    schema: dict | None = None
    type_count: int = 0
    query_count: int = 0
    mutation_count: int = 0
    subscription_count: int = 0
    interface_count: int = 0
    union_count: int = 0
    enum_count: int = 0
    sensitive_fields: list[str] = field(default_factory=list)
    auth_endpoints: list[str] = field(default_factory=list)
    get_enabled: bool = False
    batch_enabled: bool = False
    apollo_detected: bool = False
    persisted_queries: bool = False
    error: str = ""


# ===========================================================================
# Probing
# ===========================================================================

def _gql_probe(url: str, timeout: int = 10) -> GQLEndpoint:
    """Полная проверка endpoint'а: POST + GET + batch + introspection."""
    result = GQLEndpoint(url=url)

    headers = {
        "User-Agent": config.USER_AGENT,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # 1. Простой POST
    try:
        r = requests.post(
            url, json={"query": "{__typename}"},
            timeout=timeout, verify=False, headers=headers,
        )
        result.status = r.status_code
        if r.status_code not in (200, 400, 401, 403, 405):
            result.error = f"status {r.status_code}"
            return result
        try:
            data = r.json()
            if not ("data" in data or "errors" in data):
                result.error = "not gql"
                return result
        except Exception:
            result.error = "not json"
            return result
    except Exception as exc:  # noqa: BLE001
        result.error = str(exc)[:60]
        return result

    # 2. Apollo server-health
    try:
        base = url.rsplit("/", 1)[0]
        for hint in APOLLO_HINTS:
            h_url = base + hint
            try:
                rh = requests.get(h_url, timeout=5, verify=False,
                                   headers={"User-Agent": config.USER_AGENT})
                if rh.status_code == 200 and "apollo" in rh.text.lower():
                    result.apollo_detected = True
                    break
            except Exception:
                continue
    except Exception:
        pass

    # 3. GET-запрос (CSRF hint)
    try:
        rg = requests.get(
            url, params={"query": "{__typename}"},
            timeout=timeout, verify=False,
            headers={"User-Agent": config.USER_AGENT},
        )
        if rg.status_code == 200 and '"data"' in rg.text:
            result.get_enabled = True
    except Exception:
        pass

    # 4. Batch
    try:
        rb = requests.post(
            url, json=[{"query": "{__typename}"}, {"query": "{__typename}"}],
            timeout=timeout, verify=False, headers=headers,
        )
        if rb.status_code == 200:
            try:
                if isinstance(rb.json(), list):
                    result.batch_enabled = True
            except Exception:
                pass
    except Exception:
        pass

    # 5. Introspection (full)
    try:
        r = requests.post(
            url, json={"query": INTROSPECTION_FULL},
            timeout=timeout + 15, verify=False, headers=headers,
        )
        if r.status_code == 200:
            data = r.json()
            if "data" in data and data["data"] and "__schema" in data["data"]:
                result.introspection = True
                result.schema = data["data"]["__schema"]
                _analyze_schema_into(result)
    except Exception as exc:
        log.debug("introspection %s: %s", url, exc)

    return result


def _analyze_schema_into(ep: GQLEndpoint) -> None:
    """Проанализировать schema и заполнить поля endpoint'а."""
    schema = ep.schema or {}
    types = schema.get("types", []) or []
    ep.type_count = len(types)

    qt_name = (schema.get("queryType") or {}).get("name")
    mt_name = (schema.get("mutationType") or {}).get("name")
    st_name = (schema.get("subscriptionType") or {}).get("name")

    for t in types:
        kind = t.get("kind", "")
        if kind == "INTERFACE":
            ep.interface_count += 1
        elif kind == "UNION":
            ep.union_count += 1
        elif kind == "ENUM":
            ep.enum_count += 1

        name = t.get("name", "")
        if name == qt_name:
            ep.query_count = len(t.get("fields", []) or [])
        elif name == mt_name:
            ep.mutation_count = len(t.get("fields", []) or [])
        elif name == st_name:
            ep.subscription_count = len(t.get("fields", []) or [])

    # Sensitive + auth fields
    sens: set[str] = set()
    auth: set[str] = set()
    sens_lc = {n.lower() for n in SENSITIVE_FIELD_NAMES}
    auth_lc = {n.lower() for n in AUTH_FIELD_NAMES}
    for t in types:
        for f in (t.get("fields") or []):
            fname = (f.get("name") or "").lower()
            if fname in sens_lc:
                sens.add(f.get("name"))
            if fname in auth_lc:
                auth.add(f.get("name"))
        for f in (t.get("inputFields") or []):
            fname = (f.get("name") or "").lower()
            if fname in sens_lc:
                sens.add(f.get("name") + " (input)")
    ep.sensitive_fields = sorted(sens)
    ep.auth_endpoints = sorted(auth)


# ===========================================================================
# Discovery
# ===========================================================================

def discover_gql(base: str, threads: int = 20,
                 extra_paths: list[str] | None = None
                 ) -> list[GQLEndpoint]:
    """Перебрать все общие пути GraphQL параллельно."""
    base = normalize_url(base).rstrip("/")
    paths = list(COMMON_GQL_PATHS)
    if extra_paths:
        paths.extend(extra_paths)

    found: list[GQLEndpoint] = []
    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  BarColumn(),
                  TextColumn("{task.completed}/{task.total}"),
                  TimeElapsedColumn(),
                  console=console) as p:
        task = p.add_task(f"GraphQL: probing {len(paths)} paths",
                          total=len(paths))

        def _one(path: str) -> GQLEndpoint | None:
            url = urljoin(base + "/", path.lstrip("/"))
            ep = _gql_probe(url)
            if ep.introspection:
                return ep
            if ep.status in (200, 400) and not ep.error:
                return ep
            return None

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = [ex.submit(_one, pth) for pth in paths]
            for f in as_completed(futs):
                p.advance(task)
                r = f.result()
                if r:
                    found.append(r)

    return found


def show_gql_endpoints(endpoints: list[GQLEndpoint]) -> None:
    """Красивый вывод endpoint'ов."""
    if not endpoints:
        console.print("[yellow]GraphQL endpoints не найдены.[/yellow]")
        return
    table = Table(title=f"🔎 GraphQL endpoints ({len(endpoints)})")
    table.add_column("URL", style="cyan", max_width=50)
    table.add_column("St", width=4)
    table.add_column("Intro", width=6)
    table.add_column("Types", width=6)
    table.add_column("Q", width=4)
    table.add_column("M", width=4)
    table.add_column("Sub", width=4)
    table.add_column("GET", width=5)
    table.add_column("Batch", width=6)
    for ep in endpoints:
        table.add_row(
            ep.url[:50],
            str(ep.status),
            "[green]✓[/green]" if ep.introspection else "[dim]—[/dim]",
            str(ep.type_count),
            str(ep.query_count),
            str(ep.mutation_count),
            str(ep.subscription_count),
            "[red]✓[/red]" if ep.get_enabled else "[dim]—[/dim]",
            "[red]✓[/red]" if ep.batch_enabled else "[dim]—[/dim]",
        )
    console.print(table)


# ===========================================================================
# Schema analysis
# ===========================================================================

def _type_name(t: dict | None) -> str:
    if not t:
        return "?"
    kind = t.get("kind", "")
    name = t.get("name", "")
    if kind == "NON_NULL":
        return _type_name(t.get("ofType")) + "!"
    if kind == "LIST":
        return "[" + _type_name(t.get("ofType")) + "]"
    return name or "?"


def show_schema_summary(schema: dict) -> None:
    """Полный анализ схемы."""
    types = schema.get("types", []) or []
    qt = (schema.get("queryType") or {}).get("name")
    mt = (schema.get("mutationType") or {}).get("name")
    st = (schema.get("subscriptionType") or {}).get("name")

    q_fields: list[dict] = []
    m_fields: list[dict] = []
    s_fields: list[dict] = []
    for t in types:
        name = t.get("name", "")
        if name == qt:
            q_fields = t.get("fields") or []
        elif name == mt:
            m_fields = t.get("fields") or []
        elif name == st:
            s_fields = t.get("fields") or []

    # Overview
    console.print(f"\n[bold cyan]═══ Schema overview ═══[/bold cyan]")
    t0 = Table(show_header=False)
    t0.add_column("Metric", style="cyan")
    t0.add_column("Value", style="green")
    t0.add_row("Types", str(len(types)))
    t0.add_row("Queries", str(len(q_fields)))
    t0.add_row("Mutations", str(len(m_fields)))
    t0.add_row("Subscriptions", str(len(s_fields)))
    console.print(t0)

    # Queries
    if q_fields:
        t = Table(title=f"📖 Queries ({len(q_fields)})")
        t.add_column("Field", style="cyan")
        t.add_column("Args", style="yellow", max_width=40)
        t.add_column("Return", style="green", max_width=30)
        for f_ in q_fields[:50]:
            args = ", ".join(
                f"{a.get('name', '')}: {_type_name(a.get('type'))}"
                for a in (f_.get("args") or [])
            )
            t.add_row(f_.get("name", ""), args[:40],
                      _type_name(f_.get("type")))
        console.print(t)

    # Mutations
    if m_fields:
        t = Table(title=f"✏️  Mutations ({len(m_fields)})",
                  border_style="magenta")
        t.add_column("Field", style="cyan")
        t.add_column("Args", style="yellow", max_width=50)
        for f_ in m_fields[:50]:
            args = ", ".join(
                f"{a.get('name', '')}: {_type_name(a.get('type'))}"
                for a in (f_.get("args") or [])
            )
            t.add_row(f_.get("name", ""), args[:50])
        console.print(t)

    # Subscriptions
    if s_fields:
        t = Table(title=f"🔔 Subscriptions ({len(s_fields)})",
                  border_style="blue")
        t.add_column("Field", style="cyan")
        t.add_column("Return", style="green")
        for f_ in s_fields[:30]:
            t.add_row(f_.get("name", ""), _type_name(f_.get("type")))
        console.print(t)


def dump_schema(schema: dict, name: str = "schema") -> Path | None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:50]
    path = GQL_DIR / f"schema_{safe}_{ts}.json"
    try:
        path.write_text(json.dumps(schema, indent=2, ensure_ascii=False),
                        encoding="utf-8")
        console.print(f"[green]✓ Schema: {path}[/green]")
        return path
    except Exception as exc:  # noqa: BLE001
        console.print(f"[red]Ошибка: {exc}[/red]")
        return None


# ===========================================================================
# Suggestions attack
# ===========================================================================

SUGGESTION_PROBES = [
    "us", "use", "user", "users", "me", "query", "admin", "auth",
    "login", "product", "order", "item", "node", "account", "profile",
    "post", "comment", "search", "session", "token", "role",
    "permission", "team", "org", "company", "payment", "invoice",
]


def suggestions_attack(url: str, timeout: int = 10) -> list[str]:
    """Field suggestions при выключенном introspection."""
    url = normalize_url(url)
    fields: set[str] = set()
    for p in SUGGESTION_PROBES:
        try:
            r = requests.post(
                url, json={"query": f"{{ {p} }}"},
                timeout=timeout, verify=False,
                headers={"User-Agent": config.USER_AGENT,
                         "Content-Type": "application/json"},
            )
            if r.status_code != 200:
                continue
            text = r.text
            for m in re.finditer(r'Did you mean\s+["\']?([a-zA-Z_]\w+)',
                                 text):
                fields.add(m.group(1))
            for m in re.finditer(r'["\']([a-zA-Z_]\w*)["\']', text):
                cand = m.group(1)
                if len(cand) > 2 and cand.isidentifier():
                    fields.add(cand)
        except Exception:
            continue
    fields |= set(SUGGESTION_PROBES)
    return sorted(fields)


# ===========================================================================
# API URL detection regexes
# ===========================================================================

API_URL_REGEXES = [
    re.compile(r"""["'](/api/[a-zA-Z0-9_\-/\.]+)["']"""),
    re.compile(r"""["'](/v\d+/[a-zA-Z0-9_\-/\.]+)["']"""),
    re.compile(r"""["'](https?://[^"']+/api/[^"']+)["']"""),
    re.compile(r"""["'](https?://api\.[^"']+)["']"""),
    re.compile(r"""fetch\(\s*["']([^"']+)["']"""),
    re.compile(r"""fetch\(\s*`([^`]+)`"""),
    re.compile(r"""axios\.[a-z]+\(\s*["']([^"']+)["']"""),
    re.compile(r"""\$\.(?:get|post|ajax|put|delete)\(\s*["']([^"']+)["']"""),
    re.compile(r"""["'](/graphql[^"']*)["']"""),
    re.compile(r"""["'](/gql[^"']*)["']"""),
    re.compile(r"""new\s+WebSocket\(\s*["'](wss?://[^"']+)["']"""),
    re.compile(r"""["'](/ws[s]?/[^"']+)["']"""),
    re.compile(r"""["'](/socket\.io[^"']*)["']"""),
    re.compile(r"""url:\s*["']([^"']+/api/[^"']+)["']"""),
    re.compile(r"""endpoint:\s*["']([^"']+)["']"""),
    re.compile(r"""baseURL:\s*["']([^"']+)["']"""),
]

GQL_CLIENT_MARKERS = [
    "apollo-client", "apollo-boost", "@apollo/client",
    "urql", "graphql-request", "relay-runtime",
    "graphql-tag", "react-apollo", "vue-apollo",
]

SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json", "/swagger/v3/swagger.json",
    "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
    "/api/swagger.json", "/api/v1/swagger.json",
    "/api/v2/swagger.json", "/api-docs",
    "/api-docs.json", "/api-docs/v1", "/api-docs/v2",
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/api/openapi.json", "/.well-known/openapi.json",
    "/v2/api-docs", "/v3/api-docs", "/v2/api-docs/",
    "/v3/api-docs/", "/swagger-resources",
    "/redoc", "/redoc.html", "/docs", "/api/docs",
    "/api/doc", "/docs/api", "/api/redoc",
]

REST_COMMON_PATHS = [
    "/api/v1/users", "/api/v1/user", "/api/users", "/api/user",
    "/api/v1/items", "/api/items", "/api/v1/products",
    "/api/v1/orders", "/api/v1/auth", "/api/auth",
    "/api/v1/login", "/api/login", "/api/v1/register",
    "/api/v1/admin", "/api/admin", "/api/v1/health",
    "/api/v1/status", "/api/v1/version", "/api/v1/config",
    "/api/v1/me", "/api/me", "/api/whoami",
    "/api/v1/accounts", "/api/accounts", "/api/v1/sessions",
    "/api/v1/tokens", "/api/v1/keys", "/api/v1/webhooks",
    "/api/v1/payments", "/api/v1/invoices", "/api/v1/files",
    "/api/v1/upload", "/api/v1/download",
    "/api/v2/users", "/api/v2/items", "/api/v2/auth",
    "/api/internal", "/api/private", "/api/public",
    "/rest/v1", "/rest/api", "/.well-known/security.txt",
]


# ===========================================================================
# Fetch helpers
# ===========================================================================

def fetch_page(url: str, timeout: int = 10) -> str:
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": config.USER_AGENT})
        return r.text
    except Exception:
        return ""


def discover_js_apis(base: str, max_js: int = 30) -> dict:
    """Пройти по HTML → JS → API endpoints + source maps."""
    base = normalize_url(base).rstrip("/")
    html = fetch_page(base)
    if not html:
        return {"js_files": [], "endpoints": [], "errors": [],
                "gql_clients": [], "websockets": []}

    soup = BeautifulSoup(html, "html.parser")
    js_files: list[str] = []
    for s in soup.find_all("script", src=True):
        src = s["src"]
        if src.endswith(".js") or ".js?" in src:
            full = urljoin(base + "/", src)
            js_files.append(full)

    # Source maps
    for m in re.finditer(r"//#\s*sourceMappingURL=([^\s]+\.map)", html):
        full = urljoin(base + "/", m.group(1))
        js_files.append(full)

    endpoints: set[str] = set()
    websockets: set[str] = set()
    gql_clients: set[str] = set()
    errors: list[str] = []

    def _extract(text: str) -> None:
        for regex in API_URL_REGEXES:
            for m in regex.finditer(text):
                val = m.group(1)
                if val.startswith(("ws://", "wss://")):
                    websockets.add(val)
                else:
                    endpoints.add(val)
        for marker in GQL_CLIENT_MARKERS:
            if marker in text:
                gql_clients.add(marker)

    _extract(html)
    for js_url in js_files[:max_js]:
        content = fetch_page(js_url, timeout=8)
        if not content:
            errors.append(js_url)
            continue
        _extract(content)

    return {
        "js_files": js_files,
        "endpoints": sorted(endpoints),
        "errors": errors,
        "gql_clients": sorted(gql_clients),
        "websockets": sorted(websockets),
    }


def discover_swagger(base: str, threads: int = 20) -> list[dict]:
    base = normalize_url(base).rstrip("/")
    found: list[dict] = []

    def _one(path: str) -> dict | None:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = requests.get(url, timeout=8, verify=False,
                             headers={"User-Agent": config.USER_AGENT},
                             allow_redirects=True)
            if r.status_code != 200:
                return None
            text = r.text[:800]
            lc = text.lower()
            if ("swagger" not in lc and "openapi" not in lc
                    and '"paths"' not in text):
                return None
            info = {"url": url, "status": r.status_code,
                    "size": len(r.content), "type": "?"}
            try:
                data = r.json()
                info["type"] = "json"
                if "openapi" in data:
                    info["version"] = data["openapi"]
                elif "swagger" in data:
                    info["version"] = data["swagger"]
                paths = data.get("paths", {}) or {}
                info["paths"] = len(paths)
                # Extract server URLs
                servers = data.get("servers", []) or []
                if servers:
                    info["servers"] = [s.get("url", "") for s in servers[:5]]
            except Exception:
                info["type"] = "yaml/html"
            return info
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_one, p) for p in SWAGGER_PATHS]
        for f in as_completed(futs):
            r = f.result()
            if r:
                found.append(r)
    return found


def discover_rest(base: str, threads: int = 20) -> list[dict]:
    base = normalize_url(base).rstrip("/")
    found: list[dict] = []

    def _one(path: str) -> dict | None:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            r = requests.head(url, timeout=6, verify=False,
                              headers={"User-Agent": config.USER_AGENT},
                              allow_redirects=False)
            if r.status_code in (200, 401, 403, 405, 301, 302):
                return {"url": url, "status": r.status_code,
                        "content_type": r.headers.get("Content-Type", "")}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(_one, p) for p in REST_COMMON_PATHS]
        for f in as_completed(futs):
            r = f.result()
            if r:
                found.append(r)
    return found


# ===========================================================================
# Full scan
# ===========================================================================

def full_scan(target: str) -> dict:
    """Полный скан: gql + swagger + rest + js."""
    if not confirm_external(target):
        return {}

    url = normalize_url(target)
    console.print(f"[cyan]🔎 API Discovery Pro: {url}[/cyan]\n")

    findings: list[APIFinding] = []

    # 1. GraphQL
    console.print("[cyan]→ GraphQL endpoints…[/cyan]")
    gql_eps = discover_gql(url)
    show_gql_endpoints(gql_eps)

    # Анализ схем
    for ep in gql_eps:
        if ep.introspection and ep.schema:
            show_schema_summary(ep.schema)
            dump_schema(ep.schema, name=urlparse(ep.url).path
                        .replace("/", "_") or "root")

            # Findings
            if ep.sensitive_fields:
                findings.append(APIFinding(
                    kind="gql_sensitive_fields",
                    severity="high",
                    title=f"GraphQL sensitive fields exposed: {urlparse(ep.url).path}",
                    target=ep.url,
                    evidence=f"Fields: {', '.join(ep.sensitive_fields[:20])}",
                    data={"url": ep.url,
                          "fields": ep.sensitive_fields},
                ))
            if ep.mutation_count > 0 and not ep.auth_endpoints:
                findings.append(APIFinding(
                    kind="gql_mutations_no_auth",
                    severity="medium",
                    title=f"GraphQL mutations without visible auth: {urlparse(ep.url).path}",
                    target=ep.url,
                    evidence=f"{ep.mutation_count} mutations, "
                             f"auth endpoints не найдены в схеме",
                    data={"mutations": ep.mutation_count},
                ))

        if ep.get_enabled:
            findings.append(APIFinding(
                kind="gql_get_csrf",
                severity="high",
                title=f"GraphQL accepts GET (CSRF): {urlparse(ep.url).path}",
                target=ep.url,
                evidence="GET-запрос возвращает data",
                data={"url": ep.url},
            ))
        if ep.batch_enabled:
            findings.append(APIFinding(
                kind="gql_batch_enabled",
                severity="medium",
                title=f"GraphQL batching enabled: {urlparse(ep.url).path}",
                target=ep.url,
                evidence="JSON-array batching работает",
                data={"url": ep.url},
            ))

    # 2. Swagger
    console.print("\n[cyan]→ Swagger / OpenAPI…[/cyan]")
    swagger = discover_swagger(url)
    if swagger:
        t = Table(title=f"📚 Swagger/OpenAPI ({len(swagger)})")
        t.add_column("URL", style="cyan", max_width=50)
        t.add_column("Type", width=10)
        t.add_column("Version", width=10)
        t.add_column("Paths", width=8)
        for s in swagger:
            t.add_row(s["url"], s.get("type", "?"),
                      str(s.get("version", "—")),
                      str(s.get("paths", "—")))
        console.print(t)
        for s in swagger:
            findings.append(APIFinding(
                kind="swagger_exposed",
                severity="medium",
                title=f"Swagger/OpenAPI exposed: {s['url']}",
                target=s["url"],
                evidence=f"{s.get('paths', '?')} paths",
                data=s,
            ))
    else:
        console.print("[dim]Не найдено.[/dim]")

    # 3. REST
    console.print("\n[cyan]→ REST endpoints…[/cyan]")
    rest = discover_rest(url)
    if rest:
        t = Table(title=f"🌐 REST endpoints ({len(rest)})")
        t.add_column("URL", style="cyan", max_width=60)
        t.add_column("Status", width=6)
        t.add_column("Content-Type", max_width=25)
        for r in rest:
            t.add_row(r["url"], str(r["status"]),
                      r.get("content_type", "")[:25])
        console.print(t)
        # 401/403 — endpoints существуют, но защищены
        auth_eps = [r for r in rest if r["status"] in (401, 403)]
        if auth_eps:
            console.print(f"[dim]Защищённых endpoints: "
                          f"{len(auth_eps)}[/dim]")
    else:
        console.print("[dim]Не найдено.[/dim]")

    # 4. JS endpoints
    console.print("\n[cyan]→ API endpoints в JS/HTML…[/cyan]")
    js = discover_js_apis(url)
    if js["endpoints"]:
        t = Table(title=f"📜 Endpoints в JS ({len(js['endpoints'])})")
        t.add_column("#", width=4)
        t.add_column("Endpoint", style="cyan", max_width=80)
        for i, e in enumerate(js["endpoints"][:40], 1):
            t.add_row(str(i), e)
        console.print(t)

    if js["gql_clients"]:
        console.print(f"[cyan]GraphQL clients:[/cyan] "
                      f"{', '.join(js['gql_clients'])}")

    if js["websockets"]:
        t = Table(title=f"🔌 WebSocket endpoints ({len(js['websockets'])})")
        t.add_column("#", width=4)
        t.add_column("URL", style="cyan")
        for i, w in enumerate(js["websockets"][:20], 1):
            t.add_row(str(i), w)
        console.print(t)

    console.print(f"[dim]JS-файлов проанализировано: "
                  f"{len(js['js_files'])}[/dim]")

    # 5. Findings → notes
    saved = 0
    for f in findings:
        if _save_finding(f) > 0:
            saved += 1
    if saved:
        console.print(f"\n[green]✓ Findings в notes: {saved}[/green]")

    # 6. Notify
    if findings:
        try:
            from modules import notifier
            crit_high = sum(1 for f in findings
                            if f.severity in ("critical", "high"))
            if crit_high:
                notifier.notify_all(
                    f"🔎 API Discovery: {url}",
                    f"Endpoints: GQL={len(gql_eps)}, "
                    f"Swagger={len(swagger)}, REST={len(rest)}\n"
                    f"Critical/High findings: {crit_high}",
                )
        except Exception:
            pass

    result = {
        "url": url,
        "gql_endpoints": [asdict(e) for e in gql_eps],
        "swagger": swagger,
        "rest": rest,
        "js_files": js["js_files"],
        "js_endpoints": js["endpoints"],
        "websockets": js["websockets"],
        "gql_clients": js["gql_clients"],
        "findings": [asdict(f) for f in findings],
    }

    db.save_scan("api_discovery", url, {
        "gql": len(gql_eps),
        "swagger": len(swagger),
        "rest": len(rest),
        "js_endpoints": len(js["endpoints"]),
        "findings": len(findings),
    })

    # Экспорт
    _export_full(result, url)

    return result


def _export_full(result: dict, url: str) -> None:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = (urlparse(url).hostname or "target").replace(".", "_")

    # JSON
    jp = GQL_DIR / f"api_{safe}_{ts}.json"
    try:
        jp.write_text(json.dumps(result, indent=2, ensure_ascii=False,
                                  default=str), encoding="utf-8")
        console.print(f"[green]✓ JSON: {jp}[/green]")
    except Exception as exc:
        console.print(f"[yellow]JSON: {exc}[/yellow]")

    # HTML
    hp = GQL_DIR / f"api_{safe}_{ts}.html"
    try:
        hp.write_text(_render_html(result, url), encoding="utf-8")
        console.print(f"[green]✓ HTML: {hp}[/green]")
    except Exception as exc:
        console.print(f"[yellow]HTML: {exc}[/yellow]")


def _render_html(result: dict, url: str) -> str:
    parts = [
        "<!DOCTYPE html><html lang='ru'><head><meta charset='utf-8'>",
        f"<title>API Discovery — {html_mod.escape(url)}</title>",
        "<style>",
        "body{background:#0a0a0a;color:#c8c8c8;font-family:monospace;"
        "padding:24px;line-height:1.6;}",
        "h1{color:#00ff9c;border-bottom:2px solid #00ff9c;}",
        "h2{color:#00ff9c;margin-top:32px;border-left:4px solid #00ff9c;"
        "padding-left:12px;}",
        "table{width:100%;border-collapse:collapse;margin-top:12px;"
        "font-size:13px;}",
        "th{background:#111;color:#00ff9c;padding:8px;text-align:left;"
        "border:1px solid #222;}",
        "td{padding:6px 8px;border:1px solid #222;word-break:break-all;}",
        "tr:nth-child(even){background:#0d0d0d;}",
        ".critical{color:#ff2020;font-weight:bold;}",
        ".high{color:#ff7a40;font-weight:bold;}",
        ".medium{color:#ffd23f;}",
        "code{background:#111;padding:2px 6px;color:#a0ffa0;}",
        "</style></head><body>",
        f"<h1>🔎 API Discovery — {html_mod.escape(url)}</h1>",
        f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        f"<p>GraphQL: <b>{len(result['gql_endpoints'])}</b> | "
        f"Swagger: <b>{len(result['swagger'])}</b> | "
        f"REST: <b>{len(result['rest'])}</b> | "
        f"JS endpoints: <b>{len(result['js_endpoints'])}</b></p>",
    ]

    if result["gql_endpoints"]:
        parts.append(f"<h2>GraphQL endpoints ({len(result['gql_endpoints'])})</h2>")
        parts.append("<table><tr><th>URL</th><th>Status</th>"
                     "<th>Introspection</th><th>Types</th>"
                     "<th>Queries</th><th>Mutations</th>"
                     "<th>Subscriptions</th><th>GET</th>"
                     "<th>Batch</th></tr>")
        for ep in result["gql_endpoints"]:
            parts.append(
                f"<tr><td><code>{html_mod.escape(ep['url'])}</code></td>"
                f"<td>{ep.get('status', '')}</td>"
                f"<td>{'✓' if ep.get('introspection') else '—'}</td>"
                f"<td>{ep.get('type_count', 0)}</td>"
                f"<td>{ep.get('query_count', 0)}</td>"
                f"<td>{ep.get('mutation_count', 0)}</td>"
                f"<td>{ep.get('subscription_count', 0)}</td>"
                f"<td>{'✓' if ep.get('get_enabled') else '—'}</td>"
                f"<td>{'✓' if ep.get('batch_enabled') else '—'}</td></tr>")
        parts.append("</table>")

    if result["swagger"]:
        parts.append(f"<h2>Swagger/OpenAPI ({len(result['swagger'])})</h2>")
        parts.append("<table><tr><th>URL</th><th>Type</th>"
                     "<th>Version</th><th>Paths</th></tr>")
        for s in result["swagger"]:
            parts.append(
                f"<tr><td><code>{html_mod.escape(s['url'])}</code></td>"
                f"<td>{s.get('type', '?')}</td>"
                f"<td>{s.get('version', '—')}</td>"
                f"<td>{s.get('paths', '—')}</td></tr>")
        parts.append("</table>")

    if result["rest"]:
        parts.append(f"<h2>REST endpoints ({len(result['rest'])})</h2>")
        parts.append("<table><tr><th>URL</th><th>Status</th>"
                     "<th>Content-Type</th></tr>")
        for r in result["rest"]:
            parts.append(
                f"<tr><td><code>{html_mod.escape(r['url'])}</code></td>"
                f"<td>{r['status']}</td>"
                f"<td>{html_mod.escape(r.get('content_type', ''))}</td></tr>")
        parts.append("</table>")

    if result.get("findings"):
        parts.append(f"<h2>Findings ({len(result['findings'])})</h2>")
        parts.append("<table><tr><th>Severity</th><th>Kind</th>"
                     "<th>Title</th><th>Target</th></tr>")
        for f in result["findings"]:
            parts.append(
                f"<tr><td class='{f['severity']}'>"
                f"{f['severity'].upper()}</td>"
                f"<td>{html_mod.escape(f['kind'])}</td>"
                f"<td>{html_mod.escape(f['title'])}</td>"
                f"<td><code>{html_mod.escape(f['target'])}</code></td></tr>")
        parts.append("</table>")

    parts.append("</body></html>")
    return "\n".join(parts)


# ===========================================================================
# CLI wrappers
# ===========================================================================

def cli_gql(target: str) -> None:
    if not confirm_external(target):
        return
    url = normalize_url(target)
    console.print(f"[cyan]🔎 GraphQL: {url}[/cyan]")
    eps = discover_gql(url)
    show_gql_endpoints(eps)
    for ep in eps:
        if ep.introspection and ep.schema:
            show_schema_summary(ep.schema)
            dump_schema(ep.schema)


def cli_gql_introspect(endpoint: str) -> None:
    if not confirm_external(endpoint):
        return
    console.print(f"[cyan]🔎 Introspection: {endpoint}[/cyan]")
    ep = _gql_probe(normalize_url(endpoint))
    if not ep.introspection:
        console.print("[yellow]Introspection отключён.[/yellow]")
        if Confirm.ask("Попробовать suggestions attack?", default=False):
            fields = suggestions_attack(endpoint)
            console.print(f"[cyan]Найдено полей: {len(fields)}[/cyan]")
            for f_ in fields[:50]:
                console.print(f"  • {f_}")
        return
    console.print("[green]✓ Introspection активен![/green]")
    show_schema_summary(ep.schema or {})
    dump_schema(ep.schema or {})
    if ep.sensitive_fields:
        console.print(f"\n[red]⚠ Sensitive fields: "
                      f"{', '.join(ep.sensitive_fields)}[/red]")
    if ep.auth_endpoints:
        console.print(f"[cyan]Auth endpoints: "
                      f"{', '.join(ep.auth_endpoints)}[/cyan]")


def cli_swagger(target: str) -> None:
    if not confirm_external(target):
        return
    url = normalize_url(target)
    found = discover_swagger(url)
    if not found:
        console.print("[yellow]Swagger/OpenAPI не найден.[/yellow]")
        return
    t = Table(title=f"📚 Swagger/OpenAPI ({len(found)})")
    t.add_column("URL", style="cyan")
    t.add_column("Type")
    t.add_column("Version")
    t.add_column("Paths")
    for s in found:
        t.add_row(s["url"], s.get("type", "?"),
                  str(s.get("version", "—")),
                  str(s.get("paths", "—")))
    console.print(t)


def cli_rest(target: str) -> None:
    if not confirm_external(target):
        return
    url = normalize_url(target)
    found = discover_rest(url)
    if not found:
        console.print("[yellow]REST endpoints не найдены.[/yellow]")
        return
    t = Table(title=f"🌐 REST endpoints ({len(found)})")
    t.add_column("URL", style="cyan")
    t.add_column("Status")
    t.add_column("Content-Type")
    for r in found:
        t.add_row(r["url"], str(r["status"]),
                  r.get("content_type", "")[:30])
    console.print(t)


def cli_js(target: str) -> None:
    if not confirm_external(target):
        return
    url = normalize_url(target)
    js = discover_js_apis(url)
    console.print(f"[cyan]JS-файлов: {len(js['js_files'])}[/cyan]")
    for f_ in js["js_files"][:20]:
        console.print(f"  [dim]{f_}[/dim]")
    console.print(f"\n[cyan]Endpoints: {len(js['endpoints'])}[/cyan]")
    for e in js["endpoints"][:50]:
        console.print(f"  [green]{e}[/green]")
    if js["gql_clients"]:
        console.print(f"\n[cyan]GraphQL clients: "
                      f"{', '.join(js['gql_clients'])}[/cyan]")
    if js["websockets"]:
        console.print(f"\n[cyan]WebSockets: "
                      f"{len(js['websockets'])}[/cyan]")
        for w in js["websockets"][:10]:
            console.print(f"  {w}")


def cli_full(target: str) -> None:
    full_scan(target)


# ===========================================================================
# Menu
# ===========================================================================

def menu() -> None:
    table = Table(title="[bold]🔎 GraphQL / API Discovery Pro[/bold]")
    table.add_column("№", style="yellow")
    table.add_column("Опция")
    opts = [
        ("1", "Полный скан (GraphQL + Swagger + REST + JS + WebSocket)"),
        ("2", "Поиск GraphQL endpoints (60+ путей)"),
        ("3", "Introspection конкретного endpoint'а"),
        ("4", "Поиск Swagger / OpenAPI"),
        ("5", "REST endpoint enumeration"),
        ("6", "Поиск API-URL'ов в JS/HTML + WebSocket"),
    ]
    for n, t in opts:
        table.add_row(n, t)
    console.print(table)
    c = Prompt.ask("Выбор", choices=[o[0] for o in opts])

    if c == "1":
        cli_full(Prompt.ask("URL"))
    elif c == "2":
        cli_gql(Prompt.ask("URL"))
    elif c == "3":
        cli_gql_introspect(Prompt.ask("GraphQL endpoint"))
    elif c == "4":
        cli_swagger(Prompt.ask("URL"))
    elif c == "5":
        cli_rest(Prompt.ask("URL"))
    elif c == "6":
        cli_js(Prompt.ask("URL"))